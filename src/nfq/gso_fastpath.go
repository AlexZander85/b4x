package nfq

import (
	"fmt"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/sni"
	libnfqueue "github.com/florianl/go-nfqueue"
)

type gsoFastPathResult string

const (
	gsoPathNotApplicable        gsoFastPathResult = "not-applicable"
	gsoPathObserved             gsoFastPathResult = "observed"
	gsoPathAcceptedUnchanged    gsoFastPathResult = "accepted-unchanged"
	gsoPathRoutingOnly          gsoFastPathResult = "routing-only"
	gsoPathActionSuppressed     gsoFastPathResult = "action-suppressed"
	gsoPathCapabilityFailOpen   gsoFastPathResult = "capability-fail-open"
	gsoPathInputFailOpen        gsoFastPathResult = "input-fail-open"
	gsoPathAmbiguousFailOpen    gsoFastPathResult = "ambiguous-fail-open"
	gsoPathUnauthorizedFailOpen gsoFastPathResult = "unauthorized-fail-open"
)

func nfqueueOpenConfig(cfg *config.Config, queue uint16, candidate bool) libnfqueue.Config {
	out := libnfqueue.Config{
		NfQueue:      queue,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  4096,
		Copymode:     libnfqueue.NfQnlCopyPacket,
	}
	if shouldRequestNFQueueGSO(cfg, candidate) {
		out.Flags = libnfqueue.NfQaCfgFlagGSO
	}
	return out
}

func requestedGSOMode(cfg *config.Config) string {
	if cfg == nil {
		return config.GSOModeOff
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode))
	if mode == "" {
		return config.GSOModeOff
	}
	return mode
}

func shouldRequestNFQueueGSO(cfg *config.Config, candidate bool) bool {
	switch requestedGSOMode(cfg) {
	case config.GSOModeObserve:
		return candidate || (cfg != nil && cfg.Queue.IsDiscovery)
	case config.GSOModeClassify, config.GSOModeFull:
		return true
	default:
		return false
	}
}

func capabilityAllowsClassification(level GSOCapabilityLevel) bool {
	return level == GSOCapabilityClassifyReady || level == GSOCapabilityFullActionReady
}

func (w *Worker) handleGSOFastPath(vc *verdictCtx, pkt *pktInfo, cfg *config.Config, matcher *sni.SuffixSet, payload []byte, sport, dport uint16, sequence uint32, sequenceOK bool) (bool, int, gsoFastPathResult) {
	if pkt == nil || !pkt.offload.IsGSO || cfg == nil || matcher == nil || !cfg.IsTCPPort(dport) {
		return false, 0, gsoPathNotApplicable
	}
	mode := requestedGSOMode(cfg)
	if mode == config.GSOModeOff {
		return false, 0, gsoPathNotApplicable
	}
	maxBytes := cfg.System.Classifier.Runtime.Capture.NFQueue.MaxGSOBytes
	if maxBytes <= 0 {
		maxBytes = 32 * 1024
	}
	if pkt.offload.Truncated || len(payload) == 0 || len(payload) > maxBytes || int(pkt.offload.OriginalLength) > maxBytes {
		traceGSOFastPath(pkt, mode, gsoPathInputFailOpen, "truncated, empty, or over max_gso_bytes", 0)
		return true, vc.accept(), gsoPathInputFailOpen
	}
	parsed := sni.ParseTLSClientHelloMetadata(payload)
	if !parsed.Complete || parsed.SNI == "" || parsed.ECHPresent || !sequenceOK {
		traceGSOFastPath(pkt, mode, gsoPathInputFailOpen, "complete clear ClientHello unavailable", 0)
		return true, vc.accept(), gsoPathInputFailOpen
	}
	flow, ok := tcpFlowKeyForPacket(pkt, sport, dport)
	if !ok {
		traceGSOFastPath(pkt, mode, gsoPathInputFailOpen, "exact flow identity unavailable", 0)
		return true, vc.accept(), gsoPathInputFailOpen
	}
	generation := dnsHintConfigGeneration(cfg)
	clientHelloID := classifier.LogicalClientHelloID(flow, sequence, generation)
	eligible := matcher.MatchSNICandidatesWithSourceTLS(parsed.SNI, pkt.srcMac, parsed.MaxVersion, pkt.ver)
	filtered := make([]*config.SetConfig, 0, len(eligible))
	for _, candidate := range eligible {
		if candidate != nil && candidate.MatchesTCPDPort(dport) {
			filtered = append(filtered, candidate)
		}
	}

	if mode == config.GSOModeObserve {
		if !w.candidate && !cfg.Queue.IsDiscovery {
			traceGSOFastPath(pkt, mode, gsoPathCapabilityFailOpen, "observe restricted to candidate/discovery scope", clientHelloID)
			return false, 0, gsoPathCapabilityFailOpen
		}
		w.setGSOCapabilityStatus(GSOCapabilityObserveOnly, "GSO shadow classification observed in isolated scope")
		if len(filtered) == 1 {
			scope := nfqDecisionScope{FlowKey: flow, ClientHelloID: clientHelloID, EvidenceConfigGen: generation, CompleteClientHello: true, TLSVersion: parsed.MaxVersion}
			decision := w.decideNFQEvidenceScoped(cfg, pkt, dport, 6, classifier.TLSMetadata{Version: parsed.MaxVersion, ClearSNI: true, HandshakeParsed: true}, scope,
				classifier.Evidence{Source: classifier.EvidencePacketSNI, Domain: parsed.SNI, SetID: classifierSetID(filtered[0]), DomainEvidence: true})
			traceNFQDecision(decision, filtered[0], "gso-shadow")
		}
		traceGSOFastPath(pkt, mode, gsoPathObserved, "shadow decision only", clientHelloID)
		return false, 0, gsoPathObserved
	}

	status := w.GSOCapabilityStatus()
	if !capabilityAllowsClassification(status.Level) {
		traceGSOFastPath(pkt, mode, gsoPathCapabilityFailOpen, status.Reason, clientHelloID)
		return true, vc.accept(), gsoPathCapabilityFailOpen
	}
	if len(filtered) == 0 {
		traceGSOFastPath(pkt, mode, gsoPathAcceptedUnchanged, "no eligible set", clientHelloID)
		return true, vc.accept(), gsoPathAcceptedUnchanged
	}
	if len(filtered) != 1 {
		traceGSOFastPath(pkt, mode, gsoPathAmbiguousFailOpen, "multiple eligible sets", clientHelloID)
		return true, vc.accept(), gsoPathAmbiguousFailOpen
	}
	set := filtered[0]
	if w.clientHelloClaims != nil && !w.clientHelloClaims.Claim(flow, clientHelloID, generation, time.Now()) {
		traceGSOFastPath(pkt, mode, gsoPathAcceptedUnchanged, "logical ClientHello already decided", clientHelloID)
		return true, vc.accept(), gsoPathAcceptedUnchanged
	}
	scope := nfqDecisionScope{FlowKey: flow, ClientHelloID: clientHelloID, EvidenceConfigGen: generation, CompleteClientHello: true, TLSVersion: parsed.MaxVersion}
	authorized := w.allowNFQDomainDecisionScoped(cfg, pkt, dport, 6, set, classifier.EvidencePacketSNI, parsed.SNI, true, "gso-fast-path", classifier.TLSMetadata{Version: parsed.MaxVersion, ClearSNI: true, HandshakeParsed: true}, scope)
	if !authorized {
		traceGSOFastPath(pkt, mode, gsoPathUnauthorizedFailOpen, "classifier did not authorize exact flow", clientHelloID)
		return true, vc.accept(), gsoPathUnauthorizedFailOpen
	}
	if set.Routing.Enabled && config.RoutingUsesTProxy(set.Routing.Mode) {
		if w.bindAuthorizedRoute(cfg, pkt, sport, dport, 6, set, parsed.SNI, classifier.EvidencePacketSNI, 100, true) {
			traceGSOFastPath(pkt, mode, gsoPathRoutingOnly, "exact-flow route bound; skb accepted unchanged", clientHelloID)
			return true, vc.accept(), gsoPathRoutingOnly
		}
		traceGSOFastPath(pkt, mode, gsoPathUnauthorizedFailOpen, "route authorization rejected", clientHelloID)
		return true, vc.accept(), gsoPathUnauthorizedFailOpen
	}
	if gsoRequiresNormalPackets(set) {
		traceGSOFastPath(pkt, mode, gsoPathActionSuppressed, "normal TCP representation required; normalizer unavailable", clientHelloID)
		return true, vc.accept(), gsoPathActionSuppressed
	}
	traceGSOFastPath(pkt, mode, gsoPathAcceptedUnchanged, "classification complete; no packet mutation required", clientHelloID)
	return true, vc.accept(), gsoPathAcceptedUnchanged
}

func gsoRequiresNormalPackets(set *config.SetConfig) bool {
	if set == nil {
		return false
	}
	return needsTCPInjection(set) || needsTCPSynInjection(set) ||
		(set.TCP.Duplicate.Enabled && set.TCP.Duplicate.Count > 0) ||
		(set.Routing.Enabled && config.RoutingIsBlock(set.Routing.Mode)) ||
		set.TCP.IPBlockDetect.Enabled
}

func traceGSOFastPath(pkt *pktInfo, mode string, result gsoFastPathResult, reason string, clientHelloID uint64) {
	flowID := ""
	if pkt != nil {
		flowID = fmt.Sprintf("%s>%s", pkt.srcStr, pkt.dstStr)
	}
	observability.Default().Trace.Record(observability.TraceEvent{
		Timestamp: time.Now(),
		FlowID:    flowID,
		Kind:      "nfqueue_gso_fast_path",
		Fields: map[string]string{
			"mode":               mode,
			"result":             string(result),
			"reason":             reason,
			"client_hello_id":    fmt.Sprintf("%d", clientHelloID),
			"payload_length":     fmt.Sprintf("%d", pkt.offload.PayloadLength),
			"original_length":    fmt.Sprintf("%d", pkt.offload.OriginalLength),
			"checksum_not_ready": fmt.Sprintf("%t", pkt.offload.ChecksumNotReady),
		},
	})
}
