package nfq

import (
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/routing"
)

func (w *Worker) bindAuthorizedRoute(cfg *config.Config, pkt *pktInfo, sport, dport uint16, proto uint8, set *config.SetConfig, domain string, source classifier.EvidenceSource, confidence uint8, authorized bool) bool {
	if set == nil || !set.Routing.Enabled || !set.Targets.DomainOnly {
		return true
	}
	if w == nil || w.routeBindings == nil || cfg == nil || pkt == nil || !authorized {
		recordRouteBindingResult(set, "rejected", "missing exact-flow authorization")
		observeRouteScopeRejected(pkt, dport, proto, "missing exact-flow authorization")
		return false
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		recordRouteBindingResult(set, "rejected", "client scope unavailable")
		observeRouteScopeRejected(pkt, dport, proto, "client scope unavailable")
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
		observeRouteScopeRejected(pkt, dport, proto, err.Error())
		return false
	}
	observability.Default().Trace.Record(observability.TraceEvent{Timestamp: now, FlowID: fmt.Sprintf("%v", flow), Kind: "route_binding", Fields: map[string]string{
		"binding_id": binding.ID, "set_id": observability.RedactIdentifier(binding.SetID), "scope": "exact-flow", "owner": binding.Owner,
		"generation": fmt.Sprintf("%d", binding.ConfigGen), "provenance": binding.Provenance, "result": "bound",
	}})
	recordRouteBindingResult(set, "bound", "exact-flow")
	// FB-23 (Stage 33): the fallback manager is consulted only inside the
	// authorized transactional route path — after the exact-flow binding
	// commit above proved the authorization. The decision stays scoped to the
	// same client/set/generation identity as the binding; the manager itself
	// only returns route metadata (SO_MARK/rule table) and never mutates
	// sockets or iptables, so no route leak is possible here.
	if w.fallback != nil {
		family := capture.AddressFamilyIPv4
		if pkt.ver == 6 {
			family = capture.AddressFamilyIPv6
		}
		_, _ = w.fallback.Decide(routing.FlowRouteRequest{
			SetID: classifierSetID(set), Client: client, Protocol: proto,
			Family: family, Phase: classifier.PhaseResolved, Confidence: confidence,
		})
	}
	return true
}

func recordRouteBindingResult(set *config.SetConfig, result, reason string) {
	setID := ""
	if set != nil {
		setID = classifierSetID(set)
	}
	observability.Default().Metrics.Inc(observability.MetricRouteBinding, map[string]string{"result": result, "scope": "exact-flow"}, 1)
	observability.Default().Trace.Record(observability.TraceEvent{Timestamp: time.Now(), Kind: "route_binding_result", Fields: map[string]string{"set_id": observability.RedactIdentifier(setID), "result": result, "reason": reason}})
}

func observeRouteScopeRejected(pkt *pktInfo, dport uint16, proto uint8, reason string) {
	if pkt == nil {
		return
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return
	}
	_, _ = diagnostics.Default().Observe(diagnostics.FailureObservation{
		Signal: diagnostics.SignalRouteScopeRejected, Client: client, DestinationIP: netIPToAddr(pkt.dst),
		DestinationPort: dport, Protocol: proto, ObservedAt: time.Now(), Reason: reason,
	})
}
