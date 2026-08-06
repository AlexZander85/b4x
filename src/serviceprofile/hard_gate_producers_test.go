package serviceprofile

// Hard-gate producer fixtures for the service-profile WARP recommendation
// lifecycle (FB-02 sp section, §28A.11 of
// B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md).
// Each test drives the real production guard in
// src/serviceprofile/hard_gate_producers.go that emits a registered
// hard-gate metric and asserts the counter moved. All fourteen gates are
// zero-tolerance violation counters, so every fixture is a negative
// fixture: it exercises the violating branch and asserts the counter
// incremented.
//
// These tests are referenced from specs/registries/hard_gates.yaml
// (test_producer / evidence_artifact) and from
// artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.json.

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

func spCounterValue(t *testing.T, name string) uint64 {
	t.Helper()
	snap := observability.Default().Metrics.Snapshot(time.Now())
	var total uint64
	for _, counter := range snap.Counters {
		if counter.Name == name {
			total += counter.Value
		}
	}
	return total
}

func assertSPInc(t *testing.T, name string, trigger func()) {
	t.Helper()
	observability.Default().Metrics.Reset()
	before := spCounterValue(t, name)
	trigger()
	after := spCounterValue(t, name)
	if after <= before {
		t.Fatalf("%s: expected violating branch to increment counter, before=%d after=%d", name, before, after)
	}
}

func spRecommendation() TransportRecommendation {
	return TransportRecommendation{
		RecommendationID:     "rec-1",
		State:                RecommendationEligibleToTest,
		ServiceProfileID:     "svc-a",
		ComponentID:          "web",
		ClientScopeHash:      "client-a",
		SetID:                "set-1",
		BlockingProfileID:    "profile-1",
		BlockingHypothesisID: "path_local_syn_filter_probable",
		NetworkContextID:     "wan-a",
		EvidenceRefs:         []string{"ev-1", "ev-2"},
		TransportKind:        "cloudflare-warp-masque",
		TransportMode:        "base",
		FailurePolicyPreview: "fail-open",
		ConfigGen:            7,
		SessionGen:           7,
		RouteGen:             7,
		ExpiresAt:            time.Now().Add(time.Minute),
	}
}

func spWARPProjection() WARPProjection {
	return WARPProjection{
		Provider:                    "builtin",
		BundledEngineAvailable:      true,
		BaseTransportCapable:        true,
		CausalTraceReady:            true,
		PathProofSupported:          true,
		ForwardedBindingCorrelation: true,
		TargetCanarySupported:       true,
		RuntimeState:                "ready",
		SafetyHash:                  "hash-1",
	}
}

// ---- §28A.11. Recommendation hard gates -------------------------------------

func TestSPRecommendedWithoutIPPathEvidence(t *testing.T) {
	assertSPInc(t, observability.MetricSPRecommendedWithoutIPPathEvidence, func() {
		if RecommendedWithoutIPPathEvidenceAllowed(false) {
			t.Fatal("recommendation without IP-path evidence must be denied")
		}
	})
}

func TestSPRecommendedFromDestinationIPOnly(t *testing.T) {
	assertSPInc(t, observability.MetricSPRecommendedFromDestinationIPOnly, func() {
		r := spRecommendation()
		r.ClientScopeHash = ""
		if RecommendedFromDestinationIPOnlyAllowed(r) {
			t.Fatal("destination-only recommendation must be denied")
		}
	})
}

func TestSPRecommendedForOriginDead(t *testing.T) {
	assertSPInc(t, observability.MetricSPRecommendedForOriginDead, func() {
		if RecommendedForOriginDeadAllowed(false) {
			t.Fatal("origin-dead recommendation must be denied")
		}
	})
}

func TestSPRecommendedWithUnhealthyControls(t *testing.T) {
	assertSPInc(t, observability.MetricSPRecommendedWithUnhealthyControls, func() {
		if RecommendedWithUnhealthyControlsAllowed(false) {
			t.Fatal("unhealthy-controls recommendation must be denied")
		}
	})
}

func TestSPCrossServiceRecommendation(t *testing.T) {
	assertSPInc(t, observability.MetricSPCrossService, func() {
		if CrossServiceRecommendationAllowed("svc-a", "svc-b") {
			t.Fatal("cross-service recommendation must be denied")
		}
	})
}

func TestSPStaleProfileRecommendation(t *testing.T) {
	assertSPInc(t, observability.MetricSPStaleProfile, func() {
		r := spRecommendation()
		r.ExpiresAt = time.Now().Add(-time.Minute)
		if StaleProfileRecommendationAllowed(r, time.Now()) {
			t.Fatal("stale-profile recommendation must be denied")
		}
	})
}

func TestSPWithoutCausalTraceGate(t *testing.T) {
	assertSPInc(t, observability.MetricSPWithoutCausalTraceGate, func() {
		p := spWARPProjection()
		p.CausalTraceReady = false
		if WithoutCausalTraceGateAllowed(p) {
			t.Fatal("recommendation without causal-trace gate must be denied")
		}
	})
}

// TestSPRecommendedOutsideCausalEligibility (FB-31, b4x-cka): a WARP
// recommendation is denied when the blocking hypothesis does not resolve to
// a scoped-transport eligible failure family (unknown hypothesis) or when
// the evidence authority is below the family requirement (provisional hint
// never authorizes transport, FB-14 п.13).
func TestSPRecommendedOutsideCausalEligibility(t *testing.T) {
	assertSPInc(t, observability.MetricSPRecommendedOutsideCausalEligibility, func() {
		if RecommendedOutsideCausalEligibilityAllowed("no_such_hypothesis", "authoritative-abd") {
			t.Fatal("unknown hypothesis must be denied")
		}
	})
	assertSPInc(t, observability.MetricSPRecommendedOutsideCausalEligibility, func() {
		if RecommendedOutsideCausalEligibilityAllowed("path_local_syn_filter_probable", "provisional-fast") {
			t.Fatal("provisional WARP escalation must be denied")
		}
	})
	assertSPInc(t, observability.MetricSPRecommendedOutsideCausalEligibility, func() {
		if RecommendedOutsideCausalEligibilityAllowed("path_local_syn_filter_probable", "") {
			t.Fatal("empty evidence authority must be denied")
		}
	})
}

// TestSPRecommendedWithinCausalEligibilityPositive drives the allowed branch:
// an authoritative IP-filter hypothesis resolves to ip_cidr_route_block and
// must NOT increment the zero-tolerance counter.
func TestSPRecommendedWithinCausalEligibilityPositive(t *testing.T) {
	observability.Default().Metrics.Reset()
	if !RecommendedOutsideCausalEligibilityAllowed("path_local_syn_filter_probable", "authoritative-abd") {
		t.Fatal("authoritative IP-filter hypothesis must be allowed")
	}
	if after := spCounterValue(t, observability.MetricSPRecommendedOutsideCausalEligibility); after != 0 {
		t.Fatalf("allowed branch must not increment counter, got %d", after)
	}
}

func TestSPEnabledWithoutTargetCanary(t *testing.T) {
	assertSPInc(t, observability.MetricSPEnabledWithoutTargetCanary, func() {
		p := spWARPProjection()
		p.TargetCanarySupported = false
		if EnabledWithoutTargetCanaryAllowed(p, true) {
			t.Fatal("enablement without target canary must be denied")
		}
	})
}

func TestSPTestTokenReusedAsProductionAuthorization(t *testing.T) {
	assertSPInc(t, observability.MetricSPTestTokenReusedAsProdAuthorization, func() {
		tx := RecommendationTransaction{TestToken: "rec-1/test", ProductionAuthorized: true}
		if TestTokenReusedAsProductionAuthorizationAllowed(tx) {
			t.Fatal("test-token production authorization must be denied")
		}
	})
}

func TestSPIgnoredControlRegression(t *testing.T) {
	assertSPInc(t, observability.MetricSPIgnoredControlRegression, func() {
		if IgnoredControlRegressionAllowed(true, true) {
			t.Fatal("ignored control regression must be denied")
		}
	})
}

func TestSPHiddenFailPolicy(t *testing.T) {
	assertSPInc(t, observability.MetricSPHiddenFailPolicy, func() {
		if HiddenFailPolicyAllowed("") {
			t.Fatal("hidden failure policy must be denied")
		}
	})
}

func TestSPNonRUSuggestedWithoutGeoRequirement(t *testing.T) {
	assertSPInc(t, observability.MetricSPNonRUSuggestedWithoutGeoRequirement, func() {
		p := NonRUPolicy{Enabled: true, Strict: true, GeoRequirement: ""}
		if NonRUSuggestedWithoutGeoRequirementAllowed(p) {
			t.Fatal("non-ru without geo requirement must be denied")
		}
	})
}

func TestSPCamouflageSuggestedForTargetIPBlock(t *testing.T) {
	assertSPInc(t, observability.MetricSPCamouflageSuggestedForTargetIPBlock, func() {
		c := CamouflagePolicy{Enabled: true}
		if CamouflageSuggestedForTargetIPBlockAllowed(true, c) {
			t.Fatal("camouflage for target ip block must be denied")
		}
	})
}

func TestSPRecommendationCleanupFailure(t *testing.T) {
	assertSPInc(t, observability.MetricSPCleanupFailure, func() {
		v := RecommendationValidation{RecommendationID: "rec-1", CleanedUp: false}
		if RecommendationCleanupFailureAllowed(v) {
			t.Fatal("cleanup failure must be denied")
		}
	})
}
