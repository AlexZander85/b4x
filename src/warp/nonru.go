// Non-RU route-gate trace types (addendum v1.2 §73 non-RU hard gates, §62.5
// НЕ РФ gate, §62.6 DNS/IPv6 path proof). GeoObservation/GeoAttestation live
// in geo.go; this file adds the route-gate evaluation record and helpers.
// The violating-branch producers live in nonru_runtime.go.
package warp

import "time"

// NonRURouteTrace is the §73 non-RU route-gate evaluation record: whether
// the strict non-RU route is currently active, the governance attestation,
// the provider observations that produced it and the DNS/IPv6 path state.
// A strict non-RU route must never be active with a missing/failed
// attestation, any RU or disagreeing provider, direct DNS, an unvalidated
// IPv6 path or an expired attestation; a strict non-RU route must never
// silently fall back to the direct base path either.
type NonRURouteTrace struct {
	RouteActive bool
	Strict      bool

	Attestation  GeoAttestation
	Observations []GeoObservation

	DirectDNS    bool
	IPv6Enabled  bool
	IPv6Proof    bool
	FallbackToBase bool

	EvaluatedAt time.Time
}

// anyProviderRU reports whether any (non-expired) provider observation
// classifies the route's public IP as RU.
func anyProviderRU(obs []GeoObservation, now time.Time) bool {
	for _, o := range obs {
		if !o.ExpiresAt.IsZero() && !now.Before(o.ExpiresAt) {
			continue
		}
		if o.Class == GeoRU {
			return true
		}
	}
	return false
}

// attestationFresh reports whether the attestation is a current eligible
// non-RU attestation: non-RU class, not revoked, not expired, with public-IP
// and path identity (§62.5).
func attestationFresh(a GeoAttestation, now time.Time) bool {
	return a.Class == GeoNonRU && !a.Revoked && a.PublicIP != "" && a.PathID != "" &&
		!a.FreshUntil.IsZero() && now.Before(a.FreshUntil)
}

// attestationExpired reports whether the attestation window has passed
// entirely (now at or after FreshUntil).
func attestationExpired(a GeoAttestation, now time.Time) bool {
	return !a.FreshUntil.IsZero() && !now.Before(a.FreshUntil)
}