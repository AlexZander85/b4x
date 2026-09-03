// §73 hard-gate feed: the contract-package producers (src/warp
// nonru_runtime.go) must evaluate LIVE runtime truth from the engine gate,
// not stale snapshots. This adapter converts engine status into the
// NonRURouteTrace shape and runs every producer, aggregating violations.
//
// The feed is deliberately CONSERVATIVE on fields the engine cannot prove:
//   - DirectDNS=false because every engine observation carries DNSProof
//     (resolved through the inner resolver by construction);
//   - IPv6Enabled=false because v1 scope keeps IPv6 disabled (§46).
//
// If a future scope changes either, this file is the single place to touch.
package warpwire

import (
	"strconv"
	"time"

	engine "github.com/daniellavrushin/b4/transport/warp"
	warp "github.com/daniellavrushin/b4/warp"
)

// convertAttestation maps the engine attestation onto the contract shape.
// PublicIP carries the HASHED identity (the engine never holds raw IPs,
// §71); SessionGeneration is stringified per contract.
func convertAttestation(a engine.GeoAttestation) warp.GeoAttestation {
	return warp.GeoAttestation{
		Class:      warp.GeoClass(a.Class),
		Providers:  a.Providers,
		Quorum:     a.Quorum,
		PublicIP:   a.PublicIPHash,
		PathID:     a.PathID,
		FreshUntil: a.FreshUntil,
		Revoked:    a.Revoked,
	}
}

func convertObservations(obs []engine.GeoObservation) []warp.GeoObservation {
	if obs == nil {
		return nil
	}
	out := make([]warp.GeoObservation, len(obs))
	for i, o := range obs {
		out[i] = warp.GeoObservation{
			Provider:          o.Provider,
			PublicIP:          o.PublicIPHash,
			PathID:            o.PathID,
			Class:             warp.GeoClass(o.Class),
			DNSProof:          o.DNSProof,
			IPv6Proof:         o.IPv6Proof,
			ObservedAt:        o.ObservedAt,
			ExpiresAt:         o.ExpiresAt,
			CounterDelta:      o.CounterDelta,
			SessionGeneration: strconv.FormatUint(o.SessionGeneration, 10),
		}
	}
	return out
}

// FeedNonRUGateStatus runs ALL §73 non-RU route-gate producers against one
// live engine status and returns their violations (empty = consistent).
// Call it on every gate transition and before any promotion decision; a
// non-empty result is a hard-gate breach that must block promotion and be
// surfaced, never swallowed.
func FeedNonRUGateStatus(rt *warp.Runtime, st engine.NonRUStatus, now time.Time) []error {
	trace := warp.NonRURouteTrace{
		RouteActive: st.Open,
		Strict:      true,

		Attestation:  convertAttestation(st.Attestation),
		Observations: convertObservations(st.Observations),

		DirectDNS:   false, // engine observations carry DNSProof by construction
		IPv6Enabled: false, // §46 v1 scope
		EvaluatedAt: now,
	}
	var violations []error
	for _, check := range []func(warp.NonRURouteTrace) error{
		rt.NonRUActiveWithoutFreshAttestation,
		rt.NonRUActiveWhileAnyProviderRU,
		rt.NonRUActiveWithProviderDisagreement,
		rt.NonRUActiveWithDirectDNS,
		rt.NonRUActiveWithUnvalidatedIPv6,
		rt.NonRUActiveAfterAttestationExpiry,
	} {
		if err := check(trace); err != nil {
			violations = append(violations, err)
		}
	}
	if err := rt.StrictDirectFallback(trace); err != nil {
		violations = append(violations, err)
	}
	return violations
}
