package discovery

import (
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/detector"
)

// FB-31 (b4x-cka): CompileEligiblePlan is the guided-search planner entry
// point — it applies the causal eligibility matrix before hint
// compilation: forbidden candidates dropped (with their hints), mandatory
// narrower families retained, scoped transport gated by evidence authority,
// unknown family fails closed to an invalid plan.

func planCurrent(p GuidedSearchPlan) []string { return append([]string(nil), p.Baseline...) }

func TestCompileEligiblePlanFiltersForbidden(t *testing.T) {
	p := CompileEligiblePlan("dns_interception", "authoritative-abd", detector.DiscoverySearchPrior{},
		[]string{"trusted_doh", "system_forward", "scoped_transport", "direct_quic"}, nil)
	if !p.Valid() {
		t.Fatalf("plan invalid: %+v", p)
	}
	if len(p.Ordered) != 2 || p.Ordered[0] != "trusted_doh" || p.Ordered[1] != "system_forward" {
		t.Fatalf("eligible plan leaked forbidden families: %v", p.Ordered)
	}
	if !containsAny(p.Explanation, "FB-31 eligibility dropped 2 candidate(s)") {
		t.Fatalf("explanation must record dropped candidates, got %q", p.Explanation)
	}
}

func TestCompileEligiblePlanRetainsMandatoryNarrower(t *testing.T) {
	p := CompileEligiblePlan("tls_fingerprint_specific", "provisional-fast", detector.DiscoverySearchPrior{},
		[]string{"marker_split_near_sni", "generic_fake_injection"}, nil)
	// generic_fake_injection is matrix-forbidden; canonical_clienthello_profile
	// is mandatory narrower and must be retained (in baseline AND ordered —
	// mandatory families are guaranteed to be probed).
	if !sameStringSet(planCurrent(p), "marker_split_near_sni", "canonical_clienthello_profile") {
		t.Fatalf("baseline %v, want marker_split_near_sni + canonical_clienthello_profile", planCurrent(p))
	}
	if !containsCandidate(p.Ordered, "canonical_clienthello_profile") {
		t.Fatalf("mandatory narrower lost: %v", p.Ordered)
	}
	if containsCandidate(p.Ordered, "generic_fake_injection") {
		t.Fatalf("forbidden family leaked: %v", p.Ordered)
	}
}

func TestCompileEligiblePlanProvisionalBlocksWARP(t *testing.T) {
	// ip_cidr_route_block authorizes scoped transport only at
	// authoritative-abd; provisional hints never (FB-14 п.13).
	p := CompileEligiblePlan("ip_cidr_route_block", "provisional-fast", detector.DiscoverySearchPrior{},
		[]string{"scoped_transport", "ip_family_switch"}, nil)
	if containsCandidate(p.Ordered, "scoped_transport") {
		t.Fatalf("provisional plan leaked scoped_transport: %v", p.Ordered)
	}
	if len(p.Ordered) == 0 || p.Ordered[0] != "ip_family_switch" {
		t.Fatalf("provisional plan lost eligible candidates: %v", p.Ordered)
	}
}

func TestCompileEligiblePlanAuthoritativeAllowsWARP(t *testing.T) {
	p := CompileEligiblePlan("ip_cidr_route_block", "authoritative-abd", detector.DiscoverySearchPrior{},
		[]string{"scoped_transport", "ip_family_switch"}, nil)
	if !containsCandidate(p.Ordered, "scoped_transport") {
		t.Fatalf("authoritative plan must retain scoped_transport: %v", p.Ordered)
	}
}

func TestCompileEligiblePlanFiltersForbiddenHints(t *testing.T) {
	hints := []SearchHint{
		{Candidate: "trusted_doh", Action: HintBoost, Weight: 10, Provenance: "abd"},
		{Candidate: "scoped_transport", Action: HintBoost, Weight: 99, Provenance: "abd"},
	}
	p := CompileEligiblePlan("dns_interception", "authoritative-abd", detector.DiscoverySearchPrior{},
		[]string{"trusted_doh"}, hints)
	if containsCandidate(p.Ordered, "scoped_transport") {
		t.Fatalf("forbidden hint candidate leaked into plan: %v", p.Ordered)
	}
	for _, h := range p.Hints {
		if h.Candidate == "scoped_transport" {
			t.Fatalf("forbidden hint survived filter: %+v", h)
		}
	}
	if len(p.Hints) != 1 || p.Hints[0].Candidate != "trusted_doh" {
		t.Fatalf("hints = %+v, want only trusted_doh", p.Hints)
	}
}

func TestCompileEligiblePlanFailsClosedUnknownFamily(t *testing.T) {
	p := CompileEligiblePlan("NO_SUCH_FAMILY", "authoritative-abd", detector.DiscoverySearchPrior{},
		[]string{"trusted_doh", "scoped_transport"}, nil)
	if p.Valid() {
		t.Fatalf("unknown family must fail closed: %+v", p)
	}
	if len(p.Baseline) != 0 {
		t.Fatalf("unknown family baseline = %v, want empty", p.Baseline)
	}
}

func TestCompileEligiblePlanFailsClosedEverythingForbidden(t *testing.T) {
	p := CompileEligiblePlan("white_sni_evidence", "authoritative-abd", detector.DiscoverySearchPrior{},
		[]string{"white_sni_promotion", "scoped_transport"}, nil)
	if p.Valid() {
		t.Fatalf("all-forbidden family must fail closed: %+v", p)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}