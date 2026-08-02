package nfq

import (
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

func (w *Worker) configureGSONormalizer(queue uint16, secondary bool) {
	if w == nil {
		return
	}
	w.normalizerQueue = queue
	w.normalizer = secondary
}

func (w *Worker) consumeGSOPassForPacket(cfg *config.Config, pkt *pktInfo, sport, dport uint16, sequence uint32, sequenceOK bool) (GSOPassToken, *config.SetConfig, bool, string) {
	if w == nil || !w.normalizer || w.gsoPassTokens == nil || cfg == nil || pkt == nil || !sequenceOK {
		return GSOPassToken{}, nil, false, "normalizer-unavailable"
	}
	flow, ok := tcpFlowKeyForPacket(pkt, sport, dport)
	if !ok {
		return GSOPassToken{}, nil, false, "flow-unavailable"
	}
	generation := dnsHintConfigGeneration(cfg)
	clientHelloID := classifier.LogicalClientHelloID(flow, sequence, generation)
	token, ok, reason := w.gsoPassTokens.Consume(flow, clientHelloID, generation, gsoExecutionScope(w, cfg))
	if !ok {
		traceGSONormalizerMiss(flow, clientHelloID, generation, reason)
		return GSOPassToken{}, nil, false, reason
	}
	if token.Decision.Selected == nil || token.Decision.Selected.SetID == "" || !token.RequiresAction || token.ActionToken.ClientHelloID != token.ClientHelloID || token.ActionToken.ConfigGen != token.ConfigGeneration {
		traceGSONormalizerMiss(flow, clientHelloID, generation, "token-invalid")
		return GSOPassToken{}, nil, false, "token-invalid"
	}
	set := configSetByClassifierID(cfg, token.Decision.Selected.SetID)
	if set == nil || !set.MatchesTCPDPort(dport) {
		traceGSONormalizerMiss(flow, clientHelloID, generation, "set-unavailable")
		return GSOPassToken{}, nil, false, "set-unavailable"
	}
	// GSO_RUNTIME_READY: mutation is executed only while the runtime still
	// holds full-action capability and the current-generation readiness
	// verdict. A classify-to-observe downgrade after token creation revokes
	// the execution path (fail-open).
	if !gsoRuntimeReadyForExecution(w, generation) {
		traceGSONormalizerMiss(flow, clientHelloID, generation, "runtime-not-ready")
		return GSOPassToken{}, nil, false, "runtime-not-ready"
	}
	// Compact immutable references (H4): the token remains valid only while
	// the active generation resolves the same authorization and effective
	// policy digests. A revoked token fails open — the packet is accepted
	// unchanged and never mutated.
	if token.AuthorizationID != "" && authorizationDigestForGSO(flow, token.Decision.Selected.SetID, generation) != token.AuthorizationID {
		traceGSONormalizerMiss(flow, clientHelloID, generation, "authorization-revoked")
		return GSOPassToken{}, nil, false, "authorization-revoked"
	}
	if token.EffectivePolicyID != "" && effectivePolicyDigestForGSO(token.Decision.Selected.SetID, cfg.EffectiveDomainPolicy(set)) != token.EffectivePolicyID {
		traceGSONormalizerMiss(flow, clientHelloID, generation, "policy-revoked")
		return GSOPassToken{}, nil, false, "policy-revoked"
	}
	traceGSOPassToken(token, "secondary-pass", "consumed")
	return token, set, true, "consumed"
}

// gsoRuntimeReadyForExecution is the GSO_RUNTIME_READY gate for the
// normalization execution path: mutation is executed only while the worker
// holds full-action capability and the current-generation GSO_CLASSIFY_READY
// verdict is READY.
func gsoRuntimeReadyForExecution(w *Worker, generation uint64) bool {
	if w == nil || w.GSOCapabilityStatus().Level != GSOCapabilityFullActionReady {
		return false
	}
	ok, _ := w.gsoClassifyReady(generation)
	return ok
}

func configSetByClassifierID(cfg *config.Config, setID string) *config.SetConfig {
	if cfg == nil || setID == "" {
		return nil
	}
	for _, set := range cfg.Sets {
		if set != nil && classifierSetID(set) == setID {
			return set
		}
	}
	return nil
}

func traceGSONormalizerMiss(flow classifier.FlowKey, clientHelloID, generation uint64, reason string) {
	observability.Default().Metrics.Inc(observability.MetricNFQueueGSOTokenMiss, map[string]string{"reason": reason}, 1)
	observability.Default().Trace.Record(observability.TraceEvent{Timestamp: time.Now(), FlowID: fmt.Sprintf("%v", flow), Kind: "gso_normalizer_secondary", Fields: map[string]string{
		"result": "fail-open", "reason": reason, "client_hello_id": fmt.Sprintf("%d", clientHelloID), "config_generation": fmt.Sprintf("%d", generation),
	}})
}
