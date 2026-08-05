package discovery

import "testing"

// FB-31 (b4x-cka): guided search must apply the causal eligibility matrix as
// the single eligibility gate when composing candidate sets. These tests
// exercise CausalEligibleCandidates: forbidden families dropped, mandatory
// narrower families retained, scoped transport gated by evidence authority,
// unknown failure family fails closed.
func TestCausalEligibleCandidatesAppliesMatrix(t *testing.T) {
	candidates := []string{"trusted_doh", "system_forward", "scoped_transport", "direct_quic"}

	// DNS interception: scoped transport and direct QUIC are forbidden
	// regardless of authority (broad WARP escalation by DNS-only blocked).
	eligible, forbidden := CausalEligibleCandidates("dns_interception", "authoritative-abd", candidates)
	if !sameStringSet(eligible, "trusted_doh", "system_forward") {
		t.Fatalf("dns_interception eligible=%v, want trusted_doh+system_forward", eligible)
	}
	if !sameStringSet(forbidden, "scoped_transport", "direct_quic") {
		t.Fatalf("dns_interception forbidden=%v, want scoped_transport+direct_quic", forbidden)
	}

	// Single-timeout evidence: scoped transport forbidden (matrix §21.4
	// forbids only scoped_transport; direct_quic is not matrix-forbidden).
	eligible, forbidden = CausalEligibleCandidates("silent_drop_stall", "android-canary", candidates)
	if !sameStringSet(forbidden, "scoped_transport") {
		t.Fatalf("silent_drop_stall forbidden=%v, want [scoped_transport]", forbidden)
	}
	if !sameStringSet(eligible, "trusted_doh", "system_forward", "direct_quic") {
		t.Fatalf("silent_drop_stall eligible=%v", eligible)
	}

	// IP/CIDR route block: scoped transport eligible only with authoritative
	// evidence; provisional hint never authorizes it.
	ipCandidates := []string{"scoped_transport", "ip_family_switch", "target_ip_variants"}
	eligible, forbidden = CausalEligibleCandidates("ip_cidr_route_block", "provisional-fast", ipCandidates)
	if !sameStringSet(forbidden, "scoped_transport") {
		t.Fatalf("ip_cidr_route_block(provisional) forbidden=%v, want scoped_transport", forbidden)
	}
	if !sameStringSet(eligible, "ip_family_switch", "target_ip_variants") {
		t.Fatalf("ip_cidr_route_block(provisional) eligible=%v", eligible)
	}
	eligible, forbidden = CausalEligibleCandidates("ip_cidr_route_block", "authoritative-abd", ipCandidates)
	if len(forbidden) != 0 {
		t.Fatalf("ip_cidr_route_block(authoritative) forbidden=%v, want none", forbidden)
	}
	if !sameStringSet(eligible, "scoped_transport", "ip_family_switch", "target_ip_variants") {
		t.Fatalf("ip_cidr_route_block(authoritative) eligible=%v", eligible)
	}
}

func TestCausalEligibleCandidatesRetainsMandatoryNarrower(t *testing.T) {
	// §21.2 TLS/fingerprint: canonical ClientHello profiles are mandatory
	// narrower — a hint may reorder, never remove them.
	eligible, _ := CausalEligibleCandidates("tls_fingerprint_specific", "provisional-fast",
		[]string{"marker_split_near_sni", "generic_fake_injection"})
	if !sameStringSet(eligible, "marker_split_near_sni", "canonical_clienthello_profile") {
		t.Fatalf("tls_fingerprint_specific eligible=%v, mandatory narrower lost", eligible)
	}
	// §21.7 QUIC-only: TCP candidate matrix is mandatory narrower.
	eligible, _ = CausalEligibleCandidates("quic_only", "provisional-fast",
		[]string{"safe_quic_block_fallback"})
	if !sameStringSet(eligible, "safe_quic_block_fallback", "tcp_candidate_matrix") {
		t.Fatalf("quic_only eligible=%v, mandatory narrower lost", eligible)
	}
}

func TestCausalEligibleCandidatesFailsClosed(t *testing.T) {
	// Unknown failure family: nothing is eligible, everything reported as
	// forbidden — never silently select candidates outside the matrix.
	eligible, forbidden := CausalEligibleCandidates("NO_SUCH_FAMILY", "authoritative-abd", []string{"scoped_transport", "trusted_doh"})
	if len(eligible) != 0 || !sameStringSet(forbidden, "scoped_transport", "trusted_doh") {
		t.Fatalf("unknown family: eligible=%v forbidden=%v, want fail-closed", eligible, forbidden)
	}
}

func sameStringSet(got []string, want ...string) bool {
	seen := map[string]bool{}
	for _, s := range got {
		seen[s] = true
	}
	if len(seen) != len(want) {
		return false
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}
