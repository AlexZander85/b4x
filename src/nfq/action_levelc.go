package nfq

import (
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

// Level C strategies live in the action catalog and are activated only by
// explicit Runtime.Strategies flags. This file is the single production
// funnel through which they run: a strategy is resolved in the action package
// (never here), the immutable ActionPlan is compiled, and the centralized
// executor sends every write. Any planning, validation, token, budget or send
// failure fails open to the caller's legacy path. No Level C plan is ever
// built directly inside nfq; strategy selection stays in action.PlanStrategy
// and action.PlanTLSRecordSplit.

const levelCTCPPhase = "clienthello"

// levelCMarkerStrategyID returns the deterministic catalog strategy bound to
// a Runtime flag. The exact positions are owned by the action catalog; this
// mapping is the only production reference to a catalog entry by name.
func levelCMarkerStrategyID(split bool) string {
	if split {
		return "marker-host-start-end"
	}
	return "marker-small-reverse"
}

// levelCConfig returns the active config without panicking when a worker was
// created without a persisted snapshot (tests, probes).
func (w *Worker) levelCConfig() *config.Config {
	if w == nil {
		return nil
	}
	raw := w.cfg.Load()
	if raw == nil {
		return nil
	}
	cfg, ok := raw.(*config.Config)
	if !ok {
		return nil
	}
	return cfg
}

// levelCActive reports whether the runtime catalog flags request Level C
// execution. Nothing is reachable unless the config explicitly enables one
// of the marker or TLS-record techniques.
func (w *Worker) levelCActive() bool {
	cfg := w.levelCConfig()
	if cfg == nil {
		return false
	}
	s := cfg.System.Classifier.Runtime.Strategies
	return s.MarkerMultiSplit || s.MarkerMultiDisorder || s.TLSRecordSplit
}

// planLevelCStrategy resolves the strategy and compiles the immutable
// ActionPlan. It returns ok=false without touching the packet on every
// rejection: unknown catalog entry, missing tokens and incomplete markers are
// all pre-mutation failures.
func (w *Worker) planLevelCStrategy(payload []byte, seq uint32, stream action.MarkerSet, flow classifier.FlowKey, ipHdrLen, tcpHdrLen int, confidence uint8, generation uint64) (action.ActionPlan, bool) {
	if w == nil || w.actionTokens == nil || w.actionMark == 0 || !stream.Complete {
		return action.ActionPlan{}, false
	}
	cfg := w.levelCConfig()
	if cfg == nil {
		return action.ActionPlan{}, false
	}
	s := cfg.System.Classifier.Runtime.Strategies
	helloID := classifier.LogicalClientHelloID(flow, seq, generation)

	input := action.PlanInput{
		BaseSequence:  seq,
		Payload:       payload,
		Markers:       stream,
		MTU:           1500,
		IPHeaderLen:   ipHdrLen,
		TCPHeaderLen:  tcpHdrLen,
		ProcessedMark: w.actionMark,
		MaxWrites:     16,
	}

	switch {
	case s.MarkerMultiSplit || s.MarkerMultiDisorder:
		definition, err := markerStrategyByID(levelCMarkerStrategyID(s.MarkerMultiSplit))
		if err != nil {
			log.Tracef("level C: %v, failing open", err)
			return action.ActionPlan{}, false
		}
		planned, err := action.PlanStrategy(action.StrategyRequest{
			Input:               input,
			Definition:          definition,
			Confidence:          confidence,
			CompleteClientHello: stream.Complete,
			FlowHash:            flowHashOf(flow),
			ClientHelloID:       helloID,
			ConfigGen:           generation,
			Tokens:              w.actionTokens,
		})
		if err != nil {
			log.Tracef("level C marker plan rejected for %s: %v", levelCMarkerStrategyID(s.MarkerMultiSplit), err)
			return action.ActionPlan{}, false
		}
		return planned.ActionPlan, true
	case s.TLSRecordSplit:
		planned, err := action.PlanTLSRecordSplit(action.TLSRecordSplitRequest{
			Enabled:    true,
			StrategyID: "tls-record-split",
			Input:      input,
			Positions: []action.SplitPositionSpec{
				{Marker: action.MarkerHostStart},
				{Marker: action.MarkerHostEnd},
			},
			Preconditions: action.StrategyPreconditions{
				MinConfidence:      80,
				RequiresClearSNI:   true,
				RequiresCompleteCH: true,
				AllowedTCPPhases:   []string{levelCTCPPhase},
				FirstFlightOnly:    true,
			},
			Budgets:       action.DefaultActionBudgets(),
			Confidence:    confidence,
			TCPPhase:      levelCTCPPhase,
			FlowHash:      flowHashOf(flow),
			ClientHelloID: helloID,
			ConfigGen:     generation,
			Tokens:        w.actionTokens,
		})
		if err != nil {
			log.Warnf("level C TLS record split plan rejected: %v", err)
			return action.ActionPlan{}, false
		}
		return planned.ActionPlan, true
	default:
		return action.ActionPlan{}, false
	}
}

// executeLevelActionPlan runs the centralized executor on the Level C plan.
// It is strictly fail-open: any planning, validation, token or send failure
// returns false so the caller keeps its legacy direct-send behavior.
func (w *Worker) executeLevelActionPlan(raw []byte, dst net.IP, v6 bool) bool {
	if w == nil || w.actionSender == nil || w.actionMark == 0 {
		return false
	}
	if !w.levelCActive() {
		return false
	}
	if len(raw) < 40 {
		return false
	}
	ipHdrLen := 40
	if !v6 {
		ipHdrLen = int((raw[0] & 0x0F) * 4)
	}
	if len(raw) < ipHdrLen+20 {
		return false
	}
	tcpHdrLen := int((raw[ipHdrLen+12] >> 4) * 4)
	payloadStart := ipHdrLen + tcpHdrLen
	if payloadStart < ipHdrLen+20 || payloadStart >= len(raw) {
		return false
	}
	payload := raw[payloadStart:]
	if len(payload) == 0 {
		return false
	}
	seq := binary.BigEndian.Uint32(raw[ipHdrLen+4 : ipHdrLen+8])

	stream := action.DiscoverTLSMarkers(payload)
	flow := flowKeyFromPacket(raw, ipHdrLen, v6)
	cfg := w.levelCConfig()
	if cfg == nil {
		return false
	}
	confidence := cfg.System.Classifier.Runtime.Confidence.Mutate
	generation := dnsHintConfigGeneration(cfg)

	plan, ok := w.planLevelCStrategy(payload, seq, stream, flow, ipHdrLen, tcpHdrLen, confidence, generation)
	if !ok {
		log.Tracef("level C: no valid strategy plan for %s - legacy send", netAddr(dst, v6))
		return false
	}

	exec := action.NewExecutor(action.ExecutorConfig{
		MTU:           1500,
		MaxWrites:     16,
		MaxBytes:      64 * 1024,
		ProcessedMark: w.actionMark,
	}, &executorSenderAdapter{injector: w.actionSender, dst: dst, v6: v6})
	result := exec.ExecuteContext(w.ctx, raw, plan)
	if result.Applied {
		log.Tracef("level C executor applied %d write(s), %d byte(s) for %s", result.Sent, result.Bytes, netAddr(dst, v6))
		return true
	}
	log.Tracef("level C: executor failed open for %s (reason=%q) - legacy send", netAddr(dst, v6), result.Reason)
	return false
}

// flowKeyFromPacket builds the classifier key of the observed TCP packet so
// the claimed token identity is stable across retransmissions of the same
// logical ClientHello.
func flowKeyFromPacket(raw []byte, ipHdrLen int, v6 bool) classifier.FlowKey {
	if v6 {
		return classifier.NewFlowKey(classifier.ClientKey{}, addrFromSlice(raw[8:24]), addrFromSlice(raw[24:40]), binary.BigEndian.Uint16(raw[40:42]), binary.BigEndian.Uint16(raw[42:44]), 6)
	}
	return classifier.NewFlowKey(classifier.ClientKey{}, addrFromSlice(raw[12:16]), addrFromSlice(raw[16:20]), binary.BigEndian.Uint16(raw[ipHdrLen:ipHdrLen+2]), binary.BigEndian.Uint16(raw[ipHdrLen+2:ipHdrLen+4]), 6)
}

func flowHashOf(flow classifier.FlowKey) uint64 {
	return gsoFlowHash(flow)
}

func addrFromSlice(b []byte) netip.Addr {
	addr, _ := netip.AddrFromSlice(b)
	if addr.Is4In6() {
		return addr.Unmap()
	}
	return addr
}

func markerStrategyByID(id string) (action.StrategyDefinition, error) {
	for _, definition := range action.InitialMarkerStrategyCatalog() {
		if definition.ID == id {
			return definition, nil
		}
	}
	return action.StrategyDefinition{}, action.ErrStrategyInvalid
}
