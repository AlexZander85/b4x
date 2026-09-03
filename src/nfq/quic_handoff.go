package nfq

import (
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/log"
)

const quicTCPHandoffTTL = 90 * time.Second

func (w *Worker) observeQUICHandoff(cfg *config.Config, pkt *pktInfo, destinationPort uint16, host string, set *config.SetConfig) {
	w.observeQUICHandoffAt(cfg, pkt, destinationPort, host, set, time.Now())
}

// observeQUICHandoff stores both the source-scoped UDP QUIC SNI evidence and
// its short-lived TCP fallback mirror. It intentionally does not call the
// legacy global learned-IP path.
func (w *Worker) observeQUICHandoffAt(cfg *config.Config, pkt *pktInfo, destinationPort uint16, host string, set *config.SetConfig, now time.Time) {
	if cfg == nil || !cfg.System.Classifier.Flags.QUICToTCPHandoffEnabled || w.dnsHints == nil || pkt == nil || set == nil || host == "" {
		return
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return
	}
	setID := set.Id
	if setID == "" {
		setID = set.Name
	}
	for _, protocol := range []uint8{17, 6} {
		if protocol == 17 && !set.MatchesUDPDPort(destinationPort) {
			continue
		}
		if protocol == 6 && !set.MatchesTCPDPort(destinationPort) {
			continue
		}
		evidence := classifier.Evidence{
			Source:          classifier.EvidenceQUICSNI,
			Client:          client,
			DestinationIP:   netIPToAddr(pkt.dst),
			DestinationPort: destinationPort,
			L4Proto:         protocol,
			SourceDevice:    pkt.srcMac,
			Domain:          host,
			SetID:           setID,
			Confidence:      94,
			DomainEvidence:  true,
			CreatedAt:       now,
			ExpiresAt:       now.Add(quicTCPHandoffTTL),
			ConfigGen:       dnsHintConfigGeneration(cfg),
			Reason:          "source-scoped QUIC SNI with TCP fallback mirror",
		}
		_ = w.dnsHints.Observe(evidence)
		diagnostics.Default().UpdateEvidence(client, evidence.DestinationIP, destinationPort, protocol, []classifier.Evidence{evidence})
	}

	// Seek opens a new googlevideo node in the same /24 before any DNS/QUIC
	// for that exact IP. Do not /24-mirror youtubei/UI — those prefixes are
	// shared with Gmail and other Google apps.
	if !isGoogleVideoHost(host) {
		return
	}
	pfx, ok := classifier.IPv4Prefix24(netIPToAddr(pkt.dst))
	if !ok || pfx == netIPToAddr(pkt.dst) {
		return
	}
	for _, protocol := range []uint8{17, 6} {
		if protocol == 17 && !set.MatchesUDPDPort(destinationPort) {
			continue
		}
		if protocol == 6 && !set.MatchesTCPDPort(destinationPort) {
			continue
		}
		evidence := classifier.Evidence{
			Source:          classifier.EvidenceQUICSNI,
			Client:          client,
			DestinationIP:   pfx,
			DestinationPort: destinationPort,
			L4Proto:         protocol,
			SourceDevice:    pkt.srcMac,
			Domain:          host,
			SetID:           setID,
			Confidence:      88,
			DomainEvidence:  true,
			CreatedAt:       now,
			ExpiresAt:       now.Add(quicTCPHandoffTTL),
			ConfigGen:       dnsHintConfigGeneration(cfg),
			Reason:          "source-scoped QUIC googlevideo /24 TCP affinity",
		}
		if err := w.dnsHints.Observe(evidence); err != nil {
			continue
		}
		log.Tracef("QUIC googlevideo /24 handoff %s -> %s proto=%d set=%s", host, pfx, protocol, setID)
		diagnostics.Default().UpdateEvidence(client, pfx, destinationPort, protocol, []classifier.Evidence{evidence})
	}
}

// googlevideoSetForHold returns the youtube-video set from a raw host-hint
// lookup (exact IP or /24), ignoring Decide's ECH PhasePartial/non-final
// outcome. Used only to start a CH hold.
func (w *Worker) googlevideoSetForHold(cfg *config.Config, pkt *pktInfo, dport uint16) *config.SetConfig {
	if w == nil || w.dnsHints == nil || cfg == nil || pkt == nil {
		return nil
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return nil
	}
	for _, ev := range w.dnsHints.LookupForGeneration(client, netIPToAddr(pkt.dst), 6, dnsHintConfigGeneration(cfg)) {
		if !isGoogleVideoHost(ev.Domain) {
			continue
		}
		set := cfg.GetSetById(ev.SetID)
		if set == nil {
			for _, candidate := range cfg.Sets {
				if candidate != nil && (candidate.Id == ev.SetID || candidate.Name == ev.SetID) {
					set = candidate
					break
				}
			}
		}
		if set != nil && set.Enabled && set.MatchesTCPDPort(dport) {
			return set
		}
	}
	return nil
}

func isGoogleVideoHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "googlevideo.com" || strings.HasSuffix(h, ".googlevideo.com")
}
