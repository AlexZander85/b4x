// Production geo-attestation hard-gate producers (§73B geo block, addendum
// v1.2 §62.5 "Geo attestation and non-RU gate").
//
// Like the §73B producers in runtime.go and nested_runtime.go, the violating
// branches below are the production violation paths of the geo lifecycle: a
// count != 0 in a validation window is a genuine WARP geo violation, not
// synthetic telemetry. §62.5 requires that:
//
//   - each provider result is an independent event (GeoProviderTrace) and
//     must carry a route counter delta (and DNS path proof);
//   - quorum is a separate decision event (GeoQuorumTrace);
//   - a single summary event without provider events and path proof is
//     invalid;
//   - the route-gate state before/after must match the quorum decision
//     (RouteGateBefore/RouteGateAfter).
//
// geo.go stays the pure primitive (BuildGeoAttestation); this file is the
// production layer that validates the §62.5 invariants around it.
package warp

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

// GeoAttestationCommit issues one geo attestation from the provider results
// of one probe round (§62.5: each provider result is an independent event).
// A fresh provider result that carries no route counter delta (CounterDelta
// == 0) must never be part of an issued attestation -> the attestation would
// be committed without the required route counter delta
// (warp_geo_attestation_without_route_counter_delta_total).
func (rt *Runtime) GeoAttestationCommit(obs []GeoObservation, now time.Time) (GeoAttestation, error) {
	if rt == nil {
		return GeoAttestation{}, errors.New("warp runtime not initialized")
	}
	for _, o := range obs {
		if !o.ExpiresAt.IsZero() && !now.Before(o.ExpiresAt) {
			continue // expired result is not a live provider event
		}
		if o.CounterDelta == 0 {
			observability.Default().Metrics.Inc(observability.MetricWarpGeoAttestationWithoutRouteCounterDelta, nil, 1)
			return GeoAttestation{}, errors.New("geo attestation without route counter delta")
		}
	}
	return BuildGeoAttestation(obs, now), nil
}

// GeoQuorumDecision evaluates the quorum decision event (§62.5: quorum is a
// separate decision event, not derived from the attestation summary). A
// decision event with zero successful provider events — every result either
// missing the route counter delta or missing DNS path proof (or stale) — is
// invalid: "a single summary event without provider events and path proof is
// invalid" (warp_geo_quorum_without_provider_events_total).
func (rt *Runtime) GeoQuorumDecision(obs []GeoObservation, now time.Time) (GeoAttestation, error) {
	if rt == nil {
		return GeoAttestation{}, errors.New("warp runtime not initialized")
	}
	successful := 0
	for _, o := range obs {
		if !o.ExpiresAt.IsZero() && !now.Before(o.ExpiresAt) {
			continue
		}
		if o.CounterDelta == 0 || !o.DNSProof {
			continue
		}
		successful++
	}
	if successful == 0 {
		observability.Default().Metrics.Inc(observability.MetricWarpGeoQuorumWithoutProviderEvents, nil, 1)
		return GeoAttestation{}, errors.New("geo quorum decision without provider events")
	}
	return BuildGeoAttestation(obs, now), nil
}

// GeoRouteGateApply applies one quorum decision to the route gate and
// verifies the resulting route-gate state (§62.5 GeoQuorumTrace
// RouteGateBefore/RouteGateAfter). A valid fresh non-RU attestation keeps the
// gate open (transition closed->open or refresh open->open); any decision
// that leaves the after-state contradicting the decision is a route-gate
// state mismatch (warp_geo_route_gate_state_mismatch_total):
//
//   - valid attestation, gate not open after the decision    -> mismatch;
//   - invalid (revoked/expired/disagreement) attestation and
//     the gate stayed open after the decision              -> mismatch.
func (rt *Runtime) GeoRouteGateApply(a GeoAttestation, gateBefore, gateAfter string, now time.Time) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if a.Valid(now) {
		if gateAfter != "open" {
			observability.Default().Metrics.Inc(observability.MetricWarpGeoRouteGateStateMismatch, nil, 1)
			return errors.New("geo route gate state mismatch: gate not open under valid attestation")
		}
		return nil
	}
	if gateAfter != "closed" {
		observability.Default().Metrics.Inc(observability.MetricWarpGeoRouteGateStateMismatch, nil, 1)
		return errors.New("geo route gate state mismatch: gate stayed open after invalid attestation")
	}
	return nil
}
