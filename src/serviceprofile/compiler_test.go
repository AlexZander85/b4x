package serviceprofile

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/serviceprofile/schema"
)

func TestCompileDeterministic(t *testing.T) {
	m := schema.Manifest{SchemaVersion: 1, ID: "x", Name: "x", Components: []schema.Component{{ID: "c", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: "a", Role: "primary", Domains: []string{"a.example"}}}}}}
	a, e := Compile(m, CompileOptions{})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Compile(m, CompileOptions{})
	if a.SafetyHash != b.SafetyHash || a.Sets[0].ID != b.Sets[0].ID {
		t.Fatal("not deterministic")
	}
}

// TestCompileRecommendationMatrixDriven (FB-31, b4x-cka): the WARP
// recommendation compiler resolves hypothesis eligibility from the causal
// eligibility matrix, not a hardcoded list. Every hypothesis the matrix maps
// to a scoped-transport eligible family compiles to eligible-to-test;
// anything else fails closed as not-applicable. Editing the matrix breaks
// this test (mutation guard).
func TestCompileRecommendationMatrixDriven(t *testing.T) {
	now := time.Now()
	base := TransportRecommendation{
		RecommendationID:     "rec-1",
		ServiceProfileID:     "svc-a",
		ComponentID:          "web",
		ClientScopeHash:      "client-a",
		SetID:                "set-1",
		BlockingProfileID:    "profile-1",
		NetworkContextID:     "wan-a",
		EvidenceRefs:         []string{"ev-1", "ev-2"},
		TransportKind:        "cloudflare-warp-masque",
		TransportMode:        "base",
		FailurePolicyPreview: "fail-open",
	}

	// The exact hypothesis set of the matrix ip_cidr_route_block family is
	// asserted against the matrix itself, so a matrix edit that adds or
	// removes a supported hypothesis changes this test's expectation.
	for _, h := range []string{
		"path_local_syn_filter_suspected",
		"path_local_syn_filter_probable",
		"path_local_syn_filter_confirmed",
		"service_ip_filter_probable",
		"service_cidr_filter_probable",
		"shared_transport_path_block_probable",
		"multi_origin_direct_connect_failure_with_reference_success",
	} {
		r := base
		r.BlockingHypothesisID = h
		out, err := CompileRecommendation(now, r)
		if err != nil {
			t.Fatalf("hypothesis %q: unexpected error: %v", h, err)
		}
		if out.State != RecommendationEligibleToTest {
			t.Fatalf("hypothesis %q: state=%s, want eligible-to-test", h, out.State)
		}
		if !supportedIPHypothesis(h) {
			t.Fatalf("matrix-supported hypothesis %q rejected by supportedIPHypothesis", h)
		}
	}

	// Fail-closed: unknown hypothesis and non-IP hypotheses compile to
	// not-applicable, never to eligible.
	for _, h := range []string{"no_such_hypothesis", "byte_window_transfer_interference", ""} {
		r := base
		r.BlockingHypothesisID = h
		out, err := CompileRecommendation(now, r)
		if err != nil {
			t.Fatalf("hypothesis %q: unexpected error: %v", h, err)
		}
		if out.State != RecommendationNotApplicable {
			t.Fatalf("hypothesis %q: state=%s, want not-applicable", h, out.State)
		}
		if supportedIPHypothesis(h) {
			t.Fatalf("non-eligible hypothesis %q accepted by supportedIPHypothesis", h)
		}
	}
}
