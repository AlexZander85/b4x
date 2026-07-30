package nfq

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/observability"
)

func passiveRSTObservationEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.System.Classifier.Runtime.PassiveRST.Mode != config.PassiveRSTOff
}

func passiveRSTVisibilityComplete() bool {
	return ppe.DefaultVisibilityGate().Snapshot().Mode == ppe.VisibilityComplete
}

func passiveRSTSetID(set *config.SetConfig) string {
	if set == nil {
		return ""
	}
	return classifierSetID(set)
}

func (w *Worker) observePassiveRSTOutgoing(cfg *config.Config, pkt *pktInfo, tcp, payload []byte, sport, dport uint16, set *config.SetConfig) {
	if w == nil || w.normalizer || w.passiveRST == nil || !passiveRSTObservationEnabled(cfg) || pkt == nil || !cfg.IsTCPPort(dport) {
		return
	}
	flow, ok := tcpFlowKeyForPacket(pkt, sport, dport)
	if !ok {
		return
	}
	obs, ok := ParsePassiveRSTTCPObservation(pkt, tcp, len(payload), PassiveRSTClientToServer, passiveRSTVisibilityComplete(), time.Now())
	if !ok {
		return
	}
	obs.SetID = passiveRSTSetID(set)
	obs.DeviceScope = pkt.srcMac
	snapshot := w.passiveRST.ObserveOutgoing(flow, dnsHintConfigGeneration(cfg), obs)
	if tcp[13]&0x02 != 0 && tcp[13]&0x10 == 0 {
		updatePassiveRSTFailureOutcome(snapshot.FlowKey, "reconnect-attempt", obs.ObservedAt)
	}
}

func (w *Worker) observePassiveRSTIncoming(cfg *config.Config, pkt *pktInfo, tcp, payload []byte, sport, dport uint16) (PassiveRSTEnforcementResult, bool) {
	if w == nil || w.normalizer || w.passiveRST == nil || !passiveRSTObservationEnabled(cfg) || pkt == nil || !cfg.IsTCPPort(sport) {
		return PassiveRSTEnforcementResult{}, false
	}
	obs, ok := ParsePassiveRSTTCPObservation(pkt, tcp, len(payload), PassiveRSTServerToClient, passiveRSTVisibilityComplete(), time.Now())
	if !ok {
		return PassiveRSTEnforcementResult{}, false
	}
	evidence, tracked := w.passiveRST.ObserveIncoming(pkt.dstStr, pkt.srcStr, dport, sport, dnsHintConfigGeneration(cfg), obs)
	if tracked && len(payload) > 0 {
		updatePassiveRSTFailureOutcome(evidence.Flow.FlowKey, "server-progress", evidence.ObservedAt)
	}
	if !tracked || tcp[13]&0x04 == 0 {
		return PassiveRSTEnforcementResult{}, false
	}
	result := w.passiveRST.Enforce(cfg.System.Classifier.Runtime.PassiveRST, evidence)
	fields := map[string]string{
		"decision":                string(result.Decision),
		"reason":                  result.Reason,
		"requested_mode":          result.RequestedMode,
		"effective_mode":          result.EffectiveMode,
		"signal_count":            fmt.Sprintf("%d", len(evidence.Signals)),
		"strong_signals":          fmt.Sprintf("%d", result.StrongSignals),
		"corroborating_signals":   fmt.Sprintf("%d", result.CorroboratingSignals),
		"diagnostic_signals":      fmt.Sprintf("%d", result.DiagnosticSignals),
		"baseline_quality":        string(evidence.Baseline.Quality),
		"baseline_spread":         fmt.Sprintf("%d", evidence.Baseline.Spread),
		"visibility_complete":     fmt.Sprintf("%t", evidence.Flow.VisibilityComplete),
		"server_payload_progress": fmt.Sprintf("%t", evidence.Flow.ServerPayloadProgress),
		"sequence_reliable":       fmt.Sprintf("%t", evidence.Sequence.Reliable),
		"sequence_in_window":      fmt.Sprintf("%t", evidence.Sequence.InWindow),
		"ack_reliable":            fmt.Sprintf("%t", evidence.Acknowledgment.Reliable),
		"ack_in_window":           fmt.Sprintf("%t", evidence.Acknowledgment.InWindow),
		"budget_remaining":        fmt.Sprintf("%d", result.BudgetRemaining),
	}
	for i, signal := range evidence.Signals {
		fields[fmt.Sprintf("signal_%d", i)] = string(signal.Signal) + ":" + string(signal.Strength)
	}
	observability.Default().Trace.Record(observability.TraceEvent{
		Timestamp: evidence.ObservedAt,
		FlowID:    fmt.Sprintf("%v", evidence.Flow.FlowKey),
		Kind:      "passive_rst_decision",
		Fields:    fields,
	})
	reportPassiveRSTFailure(evidence, result)
	return result, true
}

func reportPassiveRSTFailure(evidence PassiveRSTEvidence, result PassiveRSTEnforcementResult) {
	flow := evidence.Flow.FlowKey.Normalize()
	destination, port, ok := passiveRSTFailureDestination(flow)
	if !ok || flow.Client.IsZero() {
		return
	}
	signal := diagnostics.SignalPassiveRSTSuspicious
	if result.Suppress() {
		signal = diagnostics.SignalPassiveRSTSuppressed
	}
	details := &diagnostics.PassiveRSTFailureDetails{
		FlowID: fmt.Sprintf("%v", flow), SetID: evidence.Flow.SetID, DeviceScope: evidence.Flow.DeviceScope,
		ConfigGeneration: evidence.Flow.ConfigGeneration, TCPPhase: passiveRSTTCPPhase(evidence.Flow), ServerPayloadProgress: evidence.Flow.ServerPayloadProgress,
		BaselineQuality: string(evidence.Baseline.Quality), BaselineSpread: evidence.Baseline.Spread,
		Sequence:          diagnostics.PassiveRSTWindowDetail{Reliable: evidence.Sequence.Reliable, InWindow: evidence.Sequence.InWindow},
		Acknowledgment:    diagnostics.PassiveRSTWindowDetail{Reliable: evidence.Acknowledgment.Reliable, InWindow: evidence.Acknowledgment.InWindow},
		OptionFingerprint: passiveRSTOptionResult(evidence), Decision: string(result.Decision), RequestedMode: result.RequestedMode,
		EffectiveMode: result.EffectiveMode, PostDecisionOutcome: "pending",
	}
	for _, observed := range evidence.Signals {
		details.Signals = append(details.Signals, diagnostics.PassiveRSTSignalDetail{Signal: string(observed.Signal), Strength: string(observed.Strength), Reason: observed.Reason})
	}
	_, _ = diagnostics.Default().Observe(diagnostics.FailureObservation{
		Signal: signal, Client: flow.Client, DestinationIP: destination, DestinationPort: port, Protocol: 6,
		ObservedAt: evidence.ObservedAt, SetCandidates: []string{evidence.Flow.SetID}, Reason: result.Reason, PassiveRST: details,
	})
}

func passiveRSTFailureDestination(flow classifier.FlowKey) (netip.Addr, uint16, bool) {
	clientIP := flow.Client.SourceIP.Unmap()
	if !clientIP.IsValid() {
		return netip.Addr{}, 0, false
	}
	if flow.SrcIP.Unmap() == clientIP {
		return flow.DstIP.Unmap(), flow.DstPort, flow.DstIP.IsValid() && flow.DstPort != 0
	}
	return flow.SrcIP.Unmap(), flow.SrcPort, flow.SrcIP.IsValid() && flow.SrcPort != 0
}

func updatePassiveRSTFailureOutcome(flow classifier.FlowKey, outcome string, observedAt time.Time) {
	destination, port, ok := passiveRSTFailureDestination(flow.Normalize())
	if !ok || flow.Client.IsZero() {
		return
	}
	diagnostics.Default().UpdatePassiveRSTOutcome(flow.Client, destination.String(), port, 6, outcome, observedAt)
}

func passiveRSTTCPPhase(flow PassiveRSTFlowSnapshot) string {
	switch {
	case flow.ServerPayloadProgress:
		return "server-payload-progress"
	case flow.SYNACKSeen:
		return "post-syn-ack-pre-payload"
	case flow.SYNSeen:
		return "syn-sent"
	default:
		return "untracked"
	}
}

func passiveRSTOptionResult(evidence PassiveRSTEvidence) string {
	for _, signal := range evidence.Signals {
		if signal.Signal == PassiveRSTSignalOptionsMismatch {
			return "mismatch"
		}
	}
	if evidence.Flow.ServerOptionsKnown && evidence.OptionsFingerprint != 0 {
		return "match"
	}
	return "unknown"
}
