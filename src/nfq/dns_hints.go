package nfq

import (
	"hash/fnv"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/dns"
	"github.com/daniellavrushin/b4/sni"
)

func (w *Worker) observeDNSResponse(cfg *config.Config, payload []byte, clientIP net.IP, sourceDevice, resolverID string) {
	if cfg == nil || !cfg.System.Classifier.Flags.ScopedDNSHintsEnabled || w.dnsHints == nil || len(payload) == 0 {
		return
	}
	client, ok := dnsClientKey(clientIP, sourceDevice)
	if !ok {
		return
	}
	observation, err := dns.ParseStructuredResponse(payload, client, resolverID, time.Now())
	if err != nil {
		// Malformed responses are diagnostic-only and never reach the hint store.
		return
	}
	matcherValue := w.matcher.Load()
	if matcherValue == nil {
		return
	}
	matcher := matcherValue.(*sni.SuffixSet)
	resolver := dns.HintSetResolverFunc(func(domain string, client classifier.ClientKey, sourceDevice string, protocol uint8) []dns.HintSetCandidate {
		matched, set := matcher.MatchSNIWithSource(domain, sourceDevice)
		if !matched || set == nil || !set.Enabled {
			return nil
		}
		if protocol == 6 && !set.MatchesTCPDPort(443) {
			return nil
		}
		if protocol == 17 && !set.MatchesUDPDPort(443) {
			return nil
		}
		setID := strings.TrimSpace(set.Id)
		if setID == "" {
			setID = strings.TrimSpace(set.Name)
		}
		if setID == "" {
			return nil
		}
		return []dns.HintSetCandidate{{SetID: setID, Confidence: 89}}
	})
	correlator := dns.NewDNSHintCorrelator(w.dnsHints, resolver)
	_, _ = correlator.ObserveResponse(observation, sourceDevice, dnsHintConfigGeneration(cfg))
	for _, answer := range observation.Answers {
		if !answer.IP.IsValid() {
			continue
		}
		for _, protocol := range []uint8{6, 17} {
			hints := w.dnsHints.Lookup(client, answer.IP, protocol)
			diagnostics.Default().UpdateEvidence(client, answer.IP, 443, protocol, hints)
		}
	}
}

func (w *Worker) matchScopedDNSHint(cfg *config.Config, pkt *pktInfo, sport, dport uint16, protocol uint8) (*config.SetConfig, bool) {
	return w.matchScopedDNSHintWithMetadata(cfg, pkt, sport, dport, protocol, classifier.TLSMetadata{})
}

func (w *Worker) matchScopedDNSHintWithMetadata(cfg *config.Config, pkt *pktInfo, sport, dport uint16, protocol uint8, tlsMetadata classifier.TLSMetadata) (*config.SetConfig, bool) {
	if !scopedClassifierEvidenceEnabled(cfg) || w.dnsHints == nil {
		return nil, false
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return nil, false
	}
	clientHints := w.dnsHints.LookupForGeneration(client, netIPToAddr(pkt.dst), protocol, dnsHintConfigGeneration(cfg))
	if len(clientHints) == 0 {
		return nil, false
	}
	flow := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), sport, dport, protocol)
	decision := classifier.Decide(classifier.DecisionContext{
		Now:             time.Now(),
		Client:          client,
		ConfigGen:       dnsHintConfigGeneration(cfg),
		DestinationPort: dport,
		L4Proto:         protocol,
		SourceDevice:    pkt.srcMac,
		TLSMetadata:     tlsMetadata,
		FlowKey:         flow,
		DomainOnlyMode:  classifierDomainOnlyMode(cfg),
		DomainOnlySet:   func(setID string) bool { return classifierSetIsDomainOnly(cfg, setID) },
	}, clientHints, classifier.DefaultConfidenceThresholds)
	if !decision.CanClassify(classifier.DefaultConfidenceThresholds) || decision.Selected == nil {
		return nil, false
	}
	set := cfg.GetSetById(decision.Selected.SetID)
	if set == nil {
		for _, candidate := range cfg.Sets {
			if candidate != nil && candidate.Name == decision.Selected.SetID {
				set = candidate
				break
			}
		}
	}
	if set == nil || !set.Enabled {
		return nil, false
	}
	if protocol == 6 && !set.MatchesTCPDPort(dport) {
		return nil, false
	}
	if protocol == 17 && !set.MatchesUDPDPort(dport) {
		return nil, false
	}
	traceNFQDecision(decision, set, "scoped-hint")
	return set, true
}

func scopedClassifierEvidenceEnabled(cfg *config.Config) bool {
	return cfg != nil && (cfg.System.Classifier.Flags.ScopedDNSHintsEnabled || cfg.System.Classifier.Flags.QUICToTCPHandoffEnabled)
}

func dnsClientKey(ip net.IP, mac string) (classifier.ClientKey, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.IsValid() {
		return classifier.ClientKey{}, false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	key := classifier.ClientKey{SourceIP: addr}
	if addr.Is4() {
		key.L3Family = 4
	} else {
		key.L3Family = 6
	}
	if parsed, err := net.ParseMAC(strings.TrimSpace(mac)); err == nil && len(parsed) == 6 {
		copy(key.SourceMAC[:], parsed)
	}
	return key, true
}

func netIPToAddr(ip net.IP) netip.Addr {
	addr, _ := netip.AddrFromSlice(ip)
	if addr.Is4In6() {
		return addr.Unmap()
	}
	return addr
}

func dnsHintConfigGeneration(cfg *config.Config) uint64 {
	if cfg == nil || strings.TrimSpace(cfg.RuntimeGeneration) == "" {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(cfg.RuntimeGeneration))
	return h.Sum64()
}
