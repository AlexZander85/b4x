package nfq

import (
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/routing"
)

func (w *Worker) bindAuthorizedRoute(cfg *config.Config, pkt *pktInfo, sport, dport uint16, proto uint8, set *config.SetConfig, domain string, source classifier.EvidenceSource, confidence uint8, authorized bool) bool {
	if set == nil || !set.Routing.Enabled || !set.Targets.DomainOnly {
		return true
	}
	if w == nil || w.routeBindings == nil || cfg == nil || pkt == nil || !authorized {
		recordRouteBindingResult(set, "rejected", "missing exact-flow authorization")
		return false
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		recordRouteBindingResult(set, "rejected", "client scope unavailable")
		return false
	}
	flow := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), sport, dport, proto)
	now := time.Now()
	auth := classifier.ActionAuthorization{
		ID:      fmt.Sprintf("route:%v:%s:%d", flow, classifierSetID(set), dnsHintConfigGeneration(cfg)),
		FlowKey: flow, Client: client, SetID: classifierSetID(set), Domain: domain, EvidenceSource: source,
		Confidence: confidence, DomainPolicy: classifierSetDomainPolicy(cfg, classifierSetID(set)), ConfigGen: dnsHintConfigGeneration(cfg),
		Final: true, ExpiresAt: now.Add(2 * time.Minute),
	}
	binding, err := w.routeBindings.Bind(routing.BindingRequest{
		Authorization: auth, Owner: "b4", Provenance: source.String(), TransactionID: cfg.RuntimeGeneration,
		RouteID: set.Routing.Mode, Timeout: 2 * time.Minute,
	}, now)
	if err != nil {
		recordRouteBindingResult(set, "rejected", err.Error())
		return false
	}
	observability.Default().Trace.Record(observability.TraceEvent{Timestamp: now, FlowID: fmt.Sprintf("%v", flow), Kind: "route_binding", Fields: map[string]string{
		"binding_id": binding.ID, "set_id": observability.RedactIdentifier(binding.SetID), "scope": "exact-flow", "owner": binding.Owner,
		"generation": fmt.Sprintf("%d", binding.ConfigGen), "provenance": binding.Provenance, "result": "bound",
	}})
	recordRouteBindingResult(set, "bound", "exact-flow")
	return true
}

func recordRouteBindingResult(set *config.SetConfig, result, reason string) {
	setID := ""
	if set != nil {
		setID = classifierSetID(set)
	}
	observability.Default().Metrics.Inc("route_binding_total", map[string]string{"result": result, "scope": "exact-flow"}, 1)
	observability.Default().Trace.Record(observability.TraceEvent{Timestamp: time.Now(), Kind: "route_binding_result", Fields: map[string]string{"set_id": observability.RedactIdentifier(setID), "result": result, "reason": reason}})
}
