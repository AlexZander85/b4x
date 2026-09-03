// Production MASQUE transport-camouflage hard-gate producers (SECT 73A
// transport camouflage hard gates, addendum v1.2 SECT C.2/C.4/C.5/C.7/C.8/
// C.10/62.7). The violating branches below are the production violation
// paths of the camouflage lifecycle (authorization -> cover SNI -> adapter
// cutoff -> candidate selection/promotion -> established bypass -> RST
// defense); a count != 0 in a validation window is a genuine WARP violation,
// not synthetic telemetry. All twelve are zero_tolerance_violation_counter
// gates:
//
//   - camouflage flow without a valid control authorization
//     (masque_camouflage_without_control_authorization_total, SECT C.2);
//   - destination-only authorization without a kernel-verifiable socket
//     identity (masque_camouflage_destination_only_authorization_total,
//     SECT C.2);
//   - payload mutation after MASQUE_ESTABLISHED
//     (masque_established_payload_mutation_total, SECT C.5 forbidden);
//   - camouflage mutation beyond the hard cutoff ceilings
//     (masque_camouflage_cutoff_failure_total, SECT C.4);
//   - control-route recursion (masque_control_route_recursion_total);
//   - a candidate/token of one instance authorizing another
//     (masque_camouflage_cross_instance_total, SECT C.8);
//   - a strategy promoted without a forwarded LAN probe
//     (masque_strategy_promoted_without_forwarded_probe_total, SECT C.7);
//   - a strategy promoted without a passed stability window
//     (masque_strategy_promoted_without_stability_window_total, SECT C.7);
//   - insecure cover TLS (masque_insecure_tls_total, SECT C.6);
//   - a failed endpoint pin accepted (masque_endpoint_pin_failure_accepted_total);
//   - unbounded candidate retry (masque_unbounded_candidate_retry_total);
//   - RST suppression without exact flow authorization
//     (masque_rst_suppression_without_exact_authorization_total, SECT C.10).
package warp

import (
	"errors"

	"github.com/daniellavrushin/b4/observability"
)

// CamouflageWithoutControlAuthorization evaluates a SECT 73A check: a
// camouflage-classified flow must carry a valid control authorization
// (inserted before the first SYN, removed on generation/endpoint/socket
// change; SECT C.2).
func (rt *Runtime) CamouflageWithoutControlAuthorization(a TransportControlAuthorization, gen, cfg uint64) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if !a.Valid(gen, cfg) {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueCamouflageWithoutControlAuthorization, nil, 1)
		return errors.New("camouflage flow without valid control authorization")
	}
	return nil
}

// CamouflageDestinationOnlyAuthorization evaluates the SECT C.2
// destination-only check: a camouflage flow authorized ONLY by the
// destination (endpoint hash) without a kernel-verifiable socket identity is
// forbidden (SocketCookie or equivalent is preferred over destination-only).
func (rt *Runtime) CamouflageDestinationOnlyAuthorization(a TransportControlAuthorization) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if a.SocketID == "" || a.FlowKey == "" {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueCamouflageDestinationOnlyAuthorization, nil, 1)
		return errors.New("camouflage authorization is destination-only without socket identity")
	}
	return nil
}

// EstablishedPayloadMutation evaluates the SECT C.5/62.7 forbidden-mutation
// check: no payload mutation after the structured CONNECT-IP success enters
// MASQUE_ESTABLISHED (post_cutoff_mutations must stay 0 once established).
func (rt *Runtime) EstablishedPayloadMutation(t CamouflageTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.ConnectIPConfirmed && t.PostCutoffMutations > 0 {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueEstablishedPayloadMutation, nil, 1)
		return errors.New("payload mutation after MASQUE_ESTABLISHED")
	}
	return nil
}

// CamouflageCutoffFailure evaluates the SECT C.4 hard-cutoff check: a
// missing lifecycle event must not leave mutation enabled indefinitely, so an
// authorized un-established adapter still mutating past any hard ceiling
// (max_packets / max_payload_bytes / max_duration) is a violation.
func (rt *Runtime) CamouflageCutoffFailure(t MasqueCutoffTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.Adapter.Valid() && t.CeilingsExceeded() {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueCamouflageCutoffFailure, nil, 1)
		return errors.New("camouflage mutation active past hard cutoff ceilings")
	}
	return nil
}

// ControlRouteRecursion evaluates the SECT 73 control-route recursion check:
// a control flow must never be routed through its own camouflage/control
// route (recursive route).
func (rt *Runtime) ControlRouteRecursion(policy DialPolicy, routeMark uint32) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if err := ValidateNoRecursion(policy, routeMark); err != nil {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueControlRouteRecursion, nil, 1)
		return errors.New("masque control route recursion detected")
	}
	return nil
}

// CamouflageCrossInstance evaluates the SECT C.8 isolation check: a
// candidate or authorization of one instance must never authorize the other
// (outer/inner independent sessions with independent tokens).
func (rt *Runtime) CamouflageCrossInstance(a TransportControlAuthorization, flowInstance string) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if a.InstanceID != "" && flowInstance != "" && a.InstanceID != flowInstance {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueCamouflageCrossInstance, nil, 1)
		return errors.New("camouflage authorization reused across instances")
	}
	return nil
}

// StrategyPromotedWithoutForwardedProbe evaluates the SECT C.7 promotion
// check: a forwarded LAN probe must pass before the strategy is promoted
// (promotion evidence list, require_forwarded_probe).
func (rt *Runtime) StrategyPromotedWithoutForwardedProbe(r CandidateResult, c Candidate) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if r.Winner && !c.Forwarded {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueStrategyPromotedWithoutForwardedProbe, nil, 1)
		return errors.New("strategy promoted without forwarded probe")
	}
	return nil
}

// StrategyPromotedWithoutStabilityWindow evaluates the SECT C.7 promotion
// check: the stability window must pass before the strategy is promoted.
func (rt *Runtime) StrategyPromotedWithoutStabilityWindow(r CandidateResult, c Candidate) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if r.Winner && !c.Stable {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueStrategyPromotedWithoutStabilityWindow, nil, 1)
		return errors.New("strategy promoted without stability window")
	}
	return nil
}

// InsecureTLSCover evaluates the SECT C.6 cover-SNI check: insecure cover
// TLS (missing endpoint pin) stays forbidden; changing cover SNI must not
// change endpoint identity/pin.
func (rt *Runtime) InsecureTLSCover(c CoverSNIConfig) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if c.Insecure() {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueInsecureTLS, nil, 1)
		return errors.New("insecure cover TLS (endpoint pin missing)")
	}
	return nil
}

// EndpointPinFailureAccepted evaluates the endpoint public-key pinning
// check: a candidate with a failed endpoint-pin verification must never be
// accepted/promoted (a strategy that requires disabling pinning is
// forbidden, SECT C.5/C.6).
func (rt *Runtime) EndpointPinFailureAccepted(r CandidateResult, endpointPinValid bool) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if r.Winner && !endpointPinValid {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueEndpointPinFailureAccepted, nil, 1)
		return errors.New("candidate promoted despite failed endpoint pin")
	}
	return nil
}

// UnboundedCandidateRetry evaluates the SECT C. bounded-retry check: auto
// candidate runs must stay inside the bounded total budget (no indefinite
// fake repeats, SECT C.5).
func (rt *Runtime) UnboundedCandidateRetry(attempts, budget uint64) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if attempts > budget {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueUnboundedCandidateRetry, nil, 1)
		return errors.New("unbounded camouflage candidate retry")
	}
	return nil
}

// RSTSuppressionWithoutExactAuthorization evaluates the SECT C.10 passive
// RST defense check: RST suppression requires exact flow visibility and
// exact authorization (enforcement stays off by default; suppression without
// exact authorization of the flow is a violation).
func (rt *Runtime) RSTSuppressionWithoutExactAuthorization(o RSTObservation, suppressed, exactAuthorized bool) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if suppressed && (o.FlowID == "" || !exactAuthorized) {
		observability.Default().Metrics.Inc(observability.MetricWarpMasqueRSTSuppressionWithoutExactAuthorization, nil, 1)
		return errors.New("rst suppression without exact flow authorization")
	}
	return nil
}