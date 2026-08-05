package validation

import (
	"testing"
)

// FB-31 (b4x-cka): the causal eligibility matrix must be deterministic,
// internally consistent and fail closed. These tests run against the
// generated Go registry only (no YAML access): positive mapping, negative
// (unknown/forbidden) cases, mutation protection, and the acceptance
// criterion that broad WARP escalation by DNS-only/QUIC-only/single-timeout
// evidence is blocked.

func TestCausalEligibilityDeclaredTotalMatches(t *testing.T) {
	if got := len(causalEligibilities); got != CausalEligibilityDeclaredTotal {
		t.Fatalf("computed failure families=%d, declared_total=%d", got, CausalEligibilityDeclaredTotal)
	}
	if got := len(causalEligibilities); got <= 0 {
		t.Fatal("causal eligibility matrix empty")
	}
}

func TestCausalEligibilityPositiveMapping(t *testing.T) {
	// §21.1 DNS interception: resolver candidates eligible, scoped transport
	// and direct QUIC forbidden, resolver-only shadow comparison.
	eligible, ok := EligibleCandidateFamilies("dns_interception")
	if !ok || !containsAll(eligible, "trusted_doh", "system_forward", "bootstrap_ip_resolver", "cname_aware_resolution") {
		t.Fatalf("dns_interception eligible=%v, want resolver families", eligible)
	}
	forbidden, ok := ForbiddenCandidateFamilies("dns_interception")
	if !ok || !containsAll(forbidden, "scoped_transport", "direct_quic") {
		t.Fatalf("dns_interception forbidden=%v, want scoped_transport+direct_quic", forbidden)
	}
	entry, ok := CausalEligibilityByFamily("dns_interception")
	if !ok || !containsAll(entry.ShadowCandidateFamilies, "resolver_only") {
		t.Fatalf("dns_interception shadow=%v, want resolver_only", entry.ShadowCandidateFamilies)
	}

	// §21.8 IP/CIDR route block: scoped transport eligible only as
	// scoped-eligible-to-test; narrower IP/target candidates preserved.
	eligible, ok = EligibleCandidateFamilies("ip_cidr_route_block")
	if !ok || !containsAll(eligible, "scoped_transport", "ip_family_switch", "target_ip_variants") {
		t.Fatalf("ip_cidr_route_block eligible=%v", eligible)
	}

	// §21.9 white SNI evidence: no eligible candidate families at all.
	if eligible, ok := EligibleCandidateFamilies("white_sni_evidence"); !ok || len(eligible) != 0 {
		t.Fatalf("white_sni_evidence eligible=%v, want none (no production eligibility)", eligible)
	}
}

func TestTransportAuthorizedBlocksBroadWARPEscalation(t *testing.T) {
	// FB-31 acceptance: broad WARP escalation by DNS-only/QUIC-only/single
	// timeout evidence is blocked — even with authoritative evidence, because
	// those failure families never declare scoped-eligible-to-test.
	for _, family := range []string{"dns_interception", "quic_only", "silent_drop_stall"} {
		if TransportAuthorized(family, "authoritative-abd") {
			t.Fatalf("TransportAuthorized(%q, authoritative-abd)=true, want false (broad WARP escalation blocked)", family)
		}
		if TransportAuthorized(family, "android-canary") {
			t.Fatalf("TransportAuthorized(%q, android-canary)=true, want false", family)
		}
	}

	// IP/CIDR route block: scoped transport requires authoritative-abd;
	// provisional hints (FB-14 п.13) never authorize transport.
	if TransportAuthorized("ip_cidr_route_block", "provisional-fast") {
		t.Fatal("TransportAuthorized(ip_cidr_route_block, provisional-fast)=true, want false (provisional hint never authorizes transport)")
	}
	if TransportAuthorized("ip_cidr_route_block", "passive-monitoring") {
		t.Fatal("TransportAuthorized(ip_cidr_route_block, passive-monitoring)=true, want false")
	}
	if !TransportAuthorized("ip_cidr_route_block", "authoritative-abd") {
		t.Fatal("TransportAuthorized(ip_cidr_route_block, authoritative-abd)=false, want true (scoped eligible-to-test)")
	}
	if !TransportAuthorized("ip_cidr_route_block", "android-canary") {
		t.Fatal("TransportAuthorized(ip_cidr_route_block, android-canary)=false, want true")
	}
}

func TestCausalEligibilityFailsClosed(t *testing.T) {
	// Unknown failure family: no mapping, no transport authorization.
	if _, ok := CausalEligibilityByFamily("NO_SUCH_FAMILY"); ok {
		t.Fatal("CausalEligibilityByFamily(unknown) resolved")
	}
	if _, ok := EligibleCandidateFamilies("NO_SUCH_FAMILY"); ok {
		t.Fatal("EligibleCandidateFamilies(unknown) resolved")
	}
	if _, ok := ForbiddenCandidateFamilies("NO_SUCH_FAMILY"); ok {
		t.Fatal("ForbiddenCandidateFamilies(unknown) resolved")
	}
	if TransportAuthorized("NO_SUCH_FAMILY", "authoritative-abd") {
		t.Fatal("TransportAuthorized(unknown family) authorized")
	}
	if TransportAuthorized("ip_cidr_route_block", "NO_SUCH_AUTHORITY") {
		t.Fatal("TransportAuthorized(unknown authority) authorized")
	}
	if TransportAuthorized("", "") {
		t.Fatal("TransportAuthorized(empty) authorized")
	}
}

func TestCausalEligibilityHypothesisMapping(t *testing.T) {
	// §21.8 hypotheses resolve to ip_cidr_route_block (the only family that
	// can authorize scoped transport) — SP-31 WARP recommendations feed
	// these hypothesis IDs.
	for _, h := range []string{
		"path_local_syn_filter_suspected",
		"path_local_syn_filter_probable",
		"path_local_syn_filter_confirmed",
		"service_ip_filter_probable",
		"service_cidr_filter_probable",
		"shared_transport_path_block_probable",
		"multi_origin_direct_connect_failure_with_reference_success",
	} {
		family, ok := CausalEligibilityFamilyForHypothesis(h)
		if !ok || family != "ip_cidr_route_block" {
			t.Fatalf("CausalEligibilityFamilyForHypothesis(%q)=(%q,%t), want ip_cidr_route_block", h, family, ok)
		}
	}
	if family, ok := CausalEligibilityFamilyForHypothesis("no_such_hypothesis"); ok || family != "" {
		t.Fatalf("unknown hypothesis resolved to (%q,%t), want fail-closed", family, ok)
	}
	// §21.6 byte-window hypothesis maps to byte_window_transfer.
	if family, ok := CausalEligibilityFamilyForHypothesis("byte_window_transfer_interference"); !ok || family != "byte_window_transfer" {
		t.Fatalf("byte_window hypothesis mapped to (%q,%t)", family, ok)
	}
}

func TestVerifyCausalEligibilityNamesGuard(t *testing.T) {
	all := CausalEligibilityFamilyNames()
	if missing := VerifyCausalEligibilityNames(all); len(missing) != 0 {
		t.Fatalf("guard rejected registered families: %v", missing)
	}
	got := VerifyCausalEligibilityNames([]string{"dns_interception", "NO_SUCH_FAMILY", ""})
	if len(got) != 2 || got[0] != "NO_SUCH_FAMILY" || got[1] != "" {
		t.Fatalf("guard returned %v, want [NO_SUCH_FAMILY \"\"]", got)
	}
}

func TestCausalEligibilityAllFamiliesGuardable(t *testing.T) {
	// Every failure family must pass the guard (guard that rejects its own
	// registry is broken) and every family must declare a title/source.
	for _, e := range causalEligibilities {
		if e.Family == "" || e.Title == "" || e.SourceDoc == "" || e.SourceSection == "" {
			t.Fatalf("failure family %q incomplete: %+v", e.Family, e)
		}
	}
}

// Mutation guard: a misspelled failure family name inside this test package
// must never silently resolve. This mirrors the FB-34.1 mutation pattern:
// any registry name change breaks the referencing test.
func TestCausalEligibilityMutationGuard(t *testing.T) {
	for _, name := range []string{"ip_cidr_route_block", "dns_interception", "quic_only"} {
		if _, ok := CausalEligibilityByFamily(name); !ok {
			t.Fatalf("registered family %q not found after mutation", name)
		}
	}
	if _, ok := CausalEligibilityByFamily("ip_cidr_route_block_typo"); ok {
		t.Fatal("mutated family name resolved")
	}
}

func containsAll(list []string, want ...string) bool {
	seen := map[string]bool{}
	for _, s := range list {
		seen[s] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}
