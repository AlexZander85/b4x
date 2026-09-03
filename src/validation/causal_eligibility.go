package validation

import "sort"

// FB-31 (b4x-cka): Causal eligibility matrix — failure family -> candidate
// family. The canonical mapping lives in
// specs/registries/causal_eligibility_matrix.yaml (generated into
// causal_eligibility.gen.go); this file carries the safety logic that
// guided search / transport fallback consume:
//
//   - TransportAuthorized: WARP/SOCKS/TUN (scoped_transport) is eligible
//     ONLY as scoped-eligible-to-test with evidence authority at or above
//     authoritative-abd (FB-30 levels). DNS-only, QUIC-only and single
//     timeout families are transport_authorization=none, so broad WARP
//     escalation by such evidence is always blocked (FB-31 acceptance).
//   - provisional hints may reorder/boost search but never authorize
//     transport (FB-14 п.13): a provisional-fast authority never satisfies
//     TransportAuthorized for scoped transport.
//   - VerifyCausalEligibilityNames fails closed on unregistered names.

// EvidenceAuthorityLevels are the FB-30 authority levels, weakest first.
// Only authoritative-abd and above may authorize scoped transport.
var EvidenceAuthorityLevels = []string{"passive-monitoring", "provisional-fast", "authoritative-abd", "android-canary"}

// MinTransportEvidenceAuthority is the minimum FB-30 authority that may
// authorize scoped transport (WARP/SOCKS/TUN).
const MinTransportEvidenceAuthority = "authoritative-abd"

// EvidenceAuthorityRank returns the rank of an FB-30 authority level, or -1
// for unknown levels.
func EvidenceAuthorityRank(authority string) int {
	for i, a := range EvidenceAuthorityLevels {
		if a == authority {
			return i
		}
	}
	return -1
}

// TransportAuthorized reports whether scoped transport (WARP/SOCKS/TUN) may
// be authorized for the failure family with the given evidence authority.
// Fails closed: unknown family, unknown authority, or authority below the
// family requirement (or below authoritative-abd) denies authorization.
// Provisional hints (provisional-fast and below) never authorize transport.
func TransportAuthorized(family, authority string) bool {
	entry, ok := CausalEligibilityByFamily(family)
	if !ok || entry.TransportAuthorization != "scoped-eligible-to-test" {
		return false
	}
	required := entry.RequiredEvidenceAuthority
	if required == "" {
		required = MinTransportEvidenceAuthority
	}
	have := EvidenceAuthorityRank(authority)
	want := EvidenceAuthorityRank(required)
	if have < 0 || want < 0 || have < want {
		return false
	}
	return have >= EvidenceAuthorityRank(MinTransportEvidenceAuthority)
}

// TransportEligibleFamily reports whether scoped transport (WARP/SOCKS/TUN)
// is eligible for the failure family at all (transport_authorization ==
// scoped-eligible-to-test), without checking evidence authority. Used by
// hypothesis-scoped callers (e.g. the WARP recommendation compiler) that
// gate authority separately. Fails closed on unknown families.
func TransportEligibleFamily(family string) bool {
	entry, ok := CausalEligibilityByFamily(family)
	return ok && entry.TransportAuthorization == "scoped-eligible-to-test"
}

// EligibleCandidateFamilies returns the eligible candidate families of a
// failure family. Fail-closed: ("", false) for unknown families.
func EligibleCandidateFamilies(family string) ([]string, bool) {
	entry, ok := CausalEligibilityByFamily(family)
	if !ok {
		return nil, false
	}
	return append([]string(nil), entry.EligibleCandidateFamilies...), true
}

// ForbiddenCandidateFamilies returns the forbidden candidate families of a
// failure family. Fail-closed: ("", false) for unknown families.
func ForbiddenCandidateFamilies(family string) ([]string, bool) {
	entry, ok := CausalEligibilityByFamily(family)
	if !ok {
		return nil, false
	}
	return append([]string(nil), entry.ForbiddenCandidateFamilies...), true
}

// MandatoryNarrowerFamilies returns the mandatory narrower families of a
// failure family. They must always be retained by guided search: a hint or
// prior may reorder, never remove them.
func MandatoryNarrowerFamilies(family string) ([]string, bool) {
	entry, ok := CausalEligibilityByFamily(family)
	if !ok {
		return nil, false
	}
	return append([]string(nil), entry.MandatoryNarrowerFamilies...), true
}

// CausalEligibilityFamilyForHypothesis resolves a blocking hypothesis ID to
// its failure family. Fail-closed: ("", false) when no family declares the
// hypothesis.
func CausalEligibilityFamilyForHypothesis(hypothesis string) (string, bool) {
	for _, entry := range causalEligibilities {
		for _, h := range entry.Hypotheses {
			if h == hypothesis {
				return entry.Family, true
			}
		}
	}
	return "", false
}

// CausalEligibilityFamilyNames returns all failure family names, sorted
// (deterministic output for reports/UI).
func CausalEligibilityFamilyNames() []string {
	out := make([]string, 0, len(causalEligibilities))
	for _, e := range causalEligibilities {
		out = append(out, e.Family)
	}
	sort.Strings(out)
	return out
}

// VerifyCausalEligibilityNames fails closed on unregistered failure family
// names (FB-34.1 pattern): returns every input name that is not a registered
// failure family, so consumers can reject it instead of silently querying an
// empty mapping. Returns nil when every name resolves.
func VerifyCausalEligibilityNames(names []string) []string {
	var missing []string
	for _, n := range names {
		if _, ok := CausalEligibilityByFamily(n); !ok {
			missing = append(missing, n)
		}
	}
	return missing
}
