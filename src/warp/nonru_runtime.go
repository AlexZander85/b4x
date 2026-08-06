// Production non-RU route-gate hard-gate producers (SECT 73 non-RU hard
// gates, addendum v1.2 sect. 62.5 НЕ РФ gate and sect. 62.6 DNS/IPv6 path
// proof). The violating branches below are the production violation paths of
// the strict non-RU route lifecycle: a count != 0 in a validation window is
// a genuine WARP violation, not synthetic telemetry. A strict non-RU route
// must never be active:
//
//   - without a fresh non-RU attestation
//     (nonru_route_active_without_fresh_attestation);
//   - while any provider classified the public IP as RU
//     (nonru_route_active_while_any_provider_ru);
//   - under provider disagreement (nonru_route_active_with_provider_disagreement);
//   - with direct DNS (nonru_route_active_with_direct_dns);
//   - with an unvalidated IPv6 path while IPv6 is enabled
//     (nonru_route_active_with_unvalidated_ipv6);
//   - after attestation expiry (nonru_route_active_after_attestation_expiry).
//
// A strict non-RU route must never silently fall back to the direct base
// path (nonru_strict_direct_fallback_total), and identity creation must
// stay within its budget (nonru_identity_creation_budget_exceeded).
package warp

import (
	"errors"

	"github.com/daniellavrushin/b4/observability"
)

// NonRUActiveWithoutFreshAttestation evaluates a §73 route-gate check: a
// strict non-RU route must not be active without a current eligible non-RU
// attestation (§62.5). Active without fresh attestation is a violation.
func (rt *Runtime) NonRUActiveWithoutFreshAttestation(t NonRURouteTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.RouteActive && !attestationFresh(t.Attestation, t.EvaluatedAt) {
		observability.Default().Metrics.Inc(observability.MetricWarpNonRUActiveWithoutFreshAttestation, nil, 1)
		return errors.New("non-ru route active without fresh attestation")
	}
	return nil
}

// NonRUActiveWhileAnyProviderRU evaluates the §73 provider-RU check: a
// strict non-RU route must not be active while any provider classified the
// observed public IP as RU (gate-close reason provider-ru, §62.5).
func (rt *Runtime) NonRUActiveWhileAnyProviderRU(t NonRURouteTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.RouteActive && anyProviderRU(t.Observations, t.EvaluatedAt) {
		observability.Default().Metrics.Inc(observability.MetricWarpNonRUActiveWhileAnyProviderRU, nil, 1)
		return errors.New("non-ru route active while any provider classifies RU")
	}
	return nil
}

// NonRUActiveWithProviderDisagreement evaluates the §73 disagreement check:
// a strict non-RU route must not be active when the attestation is in
// disagreement (provider-disagreement gate-close reason, §62.5).
func (rt *Runtime) NonRUActiveWithProviderDisagreement(t NonRURouteTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.RouteActive && t.Attestation.Class == GeoDisagreement {
		observability.Default().Metrics.Inc(observability.MetricWarpNonRUActiveWithProviderDisagreement, nil, 1)
		return errors.New("non-ru route active with provider disagreement")
	}
	return nil
}

// NonRUActiveWithDirectDNS evaluates the §73 direct-DNS check: a strict
// non-RU route must not be active while DNS resolution goes directly through
// the WAN path (dns-path-failed/§62.6; DNS must use the inner resolver).
func (rt *Runtime) NonRUActiveWithDirectDNS(t NonRURouteTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.RouteActive && t.DirectDNS {
		observability.Default().Metrics.Inc(observability.MetricWarpNonRUActiveWithDirectDNS, nil, 1)
		return errors.New("non-ru route active with direct dns")
	}
	return nil
}

// NonRUActiveWithUnvalidatedIPv6 evaluates the §73 IPv6 check: a strict
// non-RU route must not be active with an unvalidated IPv6 path while IPv6
// is enabled (§62.6 requires a current independent IPv6 path proof unless
// disabled for the exact scope).
func (rt *Runtime) NonRUActiveWithUnvalidatedIPv6(t NonRURouteTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.RouteActive && t.IPv6Enabled && !t.IPv6Proof {
		observability.Default().Metrics.Inc(observability.MetricWarpNonRUActiveWithUnvalidatedIPv6, nil, 1)
		return errors.New("non-ru route active with unvalidated ipv6 path")
	}
	return nil
}

// NonRUActiveAfterAttestationExpiry evaluates the §73 expiry check: a strict
// non-RU route must not be active after its attestation window has passed
// (gate-close reason: attestation-stale, §62.5; expired attestation must
// revoke the route before rediscovery).
func (rt *Runtime) NonRUActiveAfterAttestationExpiry(t NonRURouteTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.RouteActive && attestationExpired(t.Attestation, t.EvaluatedAt) {
		observability.Default().Metrics.Inc(observability.MetricWarpNonRUActiveAfterAttestationExpiry, nil, 1)
		return errors.New("non-ru route active after attestation expiry")
	}
	return nil
}

// StrictDirectFallback records a fallback decision of a strict non-RU route.
// A strict non-RU route must never silently fall back to the direct base
// path (manifest no-silent-fallback; only fail-closed is allowed).
func (rt *Runtime) StrictDirectFallback(t NonRURouteTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.Strict && t.FallbackToBase {
		observability.Default().Metrics.Inc(observability.MetricWarpStrictDirectFallback, nil, 1)
		return errors.New("strict non-ru route silently fell back to direct base path")
	}
	return nil
}

// IdentityCreationBudget records identity-creation accounting. Creating more
// non-RU identities than the per-generation budget allows is a violation
// (nonru_identity_creation_budget_exceeded).
func (rt *Runtime) IdentityCreationBudget(used, budget uint64) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if used > budget {
		observability.Default().Metrics.Inc(observability.MetricWarpIdentityCreationBudgetExceeded, nil, 1)
		return errors.New("identity creation budget exceeded")
	}
	return nil
}