package nfq

import (
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
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
	w.passiveRST.ObserveOutgoing(flow, dnsHintConfigGeneration(cfg), obs)
}

func (w *Worker) observePassiveRSTIncoming(cfg *config.Config, pkt *pktInfo, tcp, payload []byte, sport, dport uint16) {
	if w == nil || w.normalizer || w.passiveRST == nil || !passiveRSTObservationEnabled(cfg) || pkt == nil || !cfg.IsTCPPort(sport) {
		return
	}
	obs, ok := ParsePassiveRSTTCPObservation(pkt, tcp, len(payload), PassiveRSTServerToClient, passiveRSTVisibilityComplete(), time.Now())
	if !ok {
		return
	}
	evidence, tracked := w.passiveRST.ObserveIncoming(pkt.dstStr, pkt.srcStr, dport, sport, dnsHintConfigGeneration(cfg), obs)
	if !tracked || tcp[13]&0x04 == 0 {
		return
	}
	fields := map[string]string{
		"decision":                string(evidence.Decision),
		"requested_mode":          cfg.System.Classifier.Runtime.PassiveRST.Mode,
		"effective_mode":          config.PassiveRSTObserve,
		"signal_count":            fmt.Sprintf("%d", len(evidence.Signals)),
		"baseline_quality":        string(evidence.Baseline.Quality),
		"baseline_spread":         fmt.Sprintf("%d", evidence.Baseline.Spread),
		"visibility_complete":     fmt.Sprintf("%t", evidence.Flow.VisibilityComplete),
		"server_payload_progress": fmt.Sprintf("%t", evidence.Flow.ServerPayloadProgress),
		"sequence_reliable":       fmt.Sprintf("%t", evidence.Sequence.Reliable),
		"sequence_in_window":      fmt.Sprintf("%t", evidence.Sequence.InWindow),
		"ack_reliable":            fmt.Sprintf("%t", evidence.Acknowledgment.Reliable),
		"ack_in_window":           fmt.Sprintf("%t", evidence.Acknowledgment.InWindow),
	}
	for i, signal := range evidence.Signals {
		fields[fmt.Sprintf("signal_%d", i)] = string(signal.Signal) + ":" + string(signal.Strength)
	}
	observability.Default().Trace.Record(observability.TraceEvent{
		Timestamp: evidence.ObservedAt,
		FlowID:    fmt.Sprintf("%v", evidence.Flow.FlowKey),
		Kind:      "passive_rst_observation",
		Fields:    fields,
	})
}
