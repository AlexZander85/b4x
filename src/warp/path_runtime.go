// Production path-proof hard-gate producers (§73B path-proof block, addendum
// v1.2 §62.2 route and path proof, §62.3 forwarded-flow correlation, §62.6
// DNS and IPv6 path proof).
//
// Like the §73B producers in runtime.go, nested_runtime.go and geo_runtime.go,
// the violating branches below are the production violation paths of the
// route/path lifecycle: a count != 0 in a validation window is a genuine WARP
// path-proof violation, not synthetic telemetry. The invariants enforced here
// are:
//
//   - route/rule existence is not path proof (§62.2): promotion requires a
//     path-proof event with a positive counter delta, matching generation and
//     no direct WAN / recursion;
//   - forwarded success requires the forwarded binding trace causal chain
//     (BindingID -> RouteTokenID -> PathProofID, §62.3); a router-origin
//     probe cannot satisfy forwarded-client proof;
//   - a direct fallback must be traceable (path-probe event in the session
//     trace pipeline);
//   - strict non-RU requires current DNS path proof (§62.6) — observed path
//     equals expected path, no direct WAN;
//   - strict non-RU requires a current independent IPv6 path proof (§62.6) —
//     or IPv6 explicitly disabled for the exact scope.
package warp

import (
	"errors"

	"github.com/daniellavrushin/b4/observability"
)

// PathProofPromote promotes a route only when the promotion carries a
// path-proof event (§62.2). Route/rule existence is not path proof: a
// promotion with no proof event (empty ProofID/ProofKind), a proof that did
// not pass, a zero counter delta, or a proof that observed direct WAN or
// recursion is a violation
// (warp_route_promoted_without_path_proof_event_total).
func (rt *Runtime) PathProofPromote(session string, p TransportPathProof) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if p.ProofID == "" || p.ProofKind == "" || !p.Passed ||
		p.CounterAfterPackets <= p.CounterBeforePackets ||
		p.DirectWANObserved || p.RecursiveRouteObserved {
		observability.Default().Metrics.Inc(observability.MetricWarpRoutePromotedWithoutPathProofEvent, nil, 1)
		return errors.New("route promotion without path proof event")
	}
	return nil
}

// ForwardedSuccess records a forwarded-flow success. Real client proof MUST
// form the causal chain BindingID -> RouteTokenID -> PathProofID (§62.3); a
// router-origin probe cannot satisfy forwarded-client proof. A success
// without the binding trace is a violation
// (warp_forwarded_success_without_binding_trace_total).
func (rt *Runtime) ForwardedSuccess(session string, c ForwardedFlowCorrelation) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if c.BindingID == "" || c.RouteTokenID == "" || c.PathProofID == "" || c.RouterOrigin {
		observability.Default().Metrics.Inc(observability.MetricWarpForwardedSuccessWithoutBindingTrace, nil, 1)
		return errors.New("forwarded success without binding trace")
	}
	return nil
}

// DirectFallback switches the session to the direct/base path. The fallback
// MUST be traceable: the session trace pipeline must carry a path-probe event
// (warp_path_probe_started / warp_path_probe_passed / warp_path_probe_failed)
// for the fallback decision. A fallback with no path-probe trace at all is a
// violation (warp_direct_fallback_without_trace_total).
func (rt *Runtime) DirectFallback(session string) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	for _, e := range rt.trace.Snapshot() {
		if e.SessionID == session {
			switch e.Event {
			case "warp_path_probe_started", "warp_path_probe_passed", "warp_path_probe_failed":
				return nil
			}
		}
	}
	observability.Default().Metrics.Inc(observability.MetricWarpDirectFallbackWithoutTrace, nil, 1)
	return errors.New("direct fallback without path-probe trace")
}

// DNSPathProof validates the DNS path proof of a strict non-RU route (§62.6).
// The observed resolver path must equal the expected path, the probe must
// have passed and no direct WAN may be observed; any other state leaves the
// DNS path unproven (warp_dns_path_unproven_total).
func (rt *Runtime) DNSPathProof(t DNSPathTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.PathID == "" || !t.Passed || t.ObservedPath != t.ExpectedPath || t.DirectWANObserved {
		observability.Default().Metrics.Inc(observability.MetricWarpDNSPathUnproven, nil, 1)
		return errors.New("dns path unproven")
	}
	return nil
}

// IPv6PathProof validates the IPv6 path proof of a strict non-RU route
// (§62.6). A claimed IPv6 path must have passed with no direct WAN
// observation; any other state leaves the IPv6 path unproven
// (warp_ipv6_path_unproven_total). (When IPv6 is disabled for the exact
// selected scope no IPv6 path proof is required at all — the caller must not
// claim an IPv6 path then.)
func (rt *Runtime) IPv6PathProof(t IPFamilyPathTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.PathID == "" || !t.Passed || t.DirectWANObserved {
		observability.Default().Metrics.Inc(observability.MetricWarpIPv6PathUnproven, nil, 1)
		return errors.New("ipv6 path unproven")
	}
	return nil
}
