package discovery

// Hard-gate producer fixtures for DDI guided discovery (FB-02 DDI section,
// §32 of the DDI/TGB addendum v1.0). Each test drives the real production
// guard in src/discovery/hard_gate_producers.go that emits a registered
// hard-gate metric and asserts the counter moved. All fourteen gates are
// zero-tolerance violation counters, so every fixture is a negative
// fixture: it exercises the violating branch and asserts the counter
// incremented.
//
// These tests are referenced from specs/registries/hard_gates.yaml
// (test_producer / mutation_test / evidence_artifact) and from
// artifacts/remediation/FB02_DDI_TGB_PRODUCERS.json.

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

func ddiCounterValue(t *testing.T, name string) uint64 {
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

func assertDDIInc(t *testing.T, name string, trigger func()) {
	t.Helper()
	observability.Default().Metrics.Reset()
	before := ddiCounterValue(t, name)
	trigger()
	after := ddiCounterValue(t, name)
	if after <= before {
		t.Fatalf("%s: expected violating branch to increment counter, before=%d after=%d", name, before, after)
	}
}

func ddiProfile(t *testing.T, now time.Time) NetworkDiagnosticProfile {
	t.Helper()
	p, err := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	return p
}

func ddiContext(now time.Time) NetworkContext {
	return NewNetworkContext("wan", "eth0", "ipv4", 1, now)
}

func TestHardGateProducer_DDIContextValidation(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileWithoutContextValidation, func() {
		now := time.Now()
		ctx := ddiContext(now)
		ctx.ID = "net-other"
		UseProfileWithContext(ddiProfile(t, now), ctx, now)
	})
}

func TestHardGateProducer_DDIStaleWithoutRevalidation(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileStaleWithoutRevalidation, func() {
		now := time.Now()
		p := ddiProfile(t, now)
		p.ExpiresAt = now.Add(-time.Minute)
		UseProfileRevalidated(p, now, false)
	})
}

func TestHardGateProducer_DDICrossWANUse(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileCrossWANUse, func() {
		UseProfileSameWAN(ddiProfile(t, time.Now()), "wan-other")
	})
}

func TestHardGateProducer_DDIMutableRuntimePointer(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileMutableRuntimePointer, func() {
		RuntimeProfileBinding(true)
	})
}

func TestHardGateProducer_DDIHintWithoutProvenance(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileHintWithoutProvenance, func() {
		UseSearchHint(SearchHint{Candidate: "10.0.0.1", Action: HintBoost, Weight: 5})
	})
}

func TestHardGateProducer_DDIHintOverrodeBaseline(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileHintOverrodeBaseline, func() {
		plan := GuidedSearchPlan{Baseline: []string{"1.1.1.1"}, Ordered: []string{"2.2.2.2", "1.1.1.1"}, ExhaustiveFallback: true}
		HintOrderRespectsBaseline(plan)
	})
}

// TestHardGateProducer_DDIOutsideCausalEligibility (FB-31, b4x-cka): a
// guided plan that leaks a matrix-forbidden family into Ordered is denied
// and increments the zero-tolerance counter; unknown failure family fails
// closed.
func TestHardGateProducer_DDIOutsideCausalEligibility(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileOutsideCausalEligibility, func() {
		plan := GuidedSearchPlan{Baseline: []string{"trusted_doh"}, Ordered: []string{"trusted_doh", "scoped_transport"}, ExhaustiveFallback: true}
		if GuidedPlanWithinCausalEligibility(plan, "dns_interception", "authoritative-abd") {
			t.Fatal("scoped_transport forbidden for dns_interception must be denied")
		}
	})
	assertDDIInc(t, observability.MetricDiscoveryProfileOutsideCausalEligibility, func() {
		plan := GuidedSearchPlan{Baseline: []string{"scoped_transport"}, Ordered: []string{"scoped_transport"}, ExhaustiveFallback: true}
		if GuidedPlanWithinCausalEligibility(plan, "ip_cidr_route_block", "provisional-fast") {
			t.Fatal("provisional WARP escort must be denied")
		}
	})
	assertDDIInc(t, observability.MetricDiscoveryProfileOutsideCausalEligibility, func() {
		plan := GuidedSearchPlan{Baseline: []string{"trusted_doh"}, Ordered: []string{"trusted_doh"}, ExhaustiveFallback: true}
		if GuidedPlanWithinCausalEligibility(plan, "NO_SUCH_FAMILY", "authoritative-abd") {
			t.Fatal("unknown failure family must be denied")
		}
	})
}

// TestHardGateProducer_DDIWithinCausalEligibilityPositive drives the allowed
// branch: an eligible plan (mandatory narrower retained, authoritative
// scoped transport) must NOT increment the zero-tolerance counter.
func TestHardGateProducer_DDIWithinCausalEligibilityPositive(t *testing.T) {
	observability.Default().Metrics.Reset()
	plan := GuidedSearchPlan{
		Baseline:           []string{"ip_family_switch"},
		Ordered:            []string{"ip_family_switch", "scoped_transport"},
		ExhaustiveFallback: true,
	}
	if !GuidedPlanWithinCausalEligibility(plan, "ip_cidr_route_block", "authoritative-abd") {
		t.Fatal("authoritative scoped-transport plan must be allowed")
	}
	plan = GuidedSearchPlan{Baseline: []string{"marker_split_near_sni"}, Ordered: []string{"marker_split_near_sni", "canonical_clienthello_profile"}, ExhaustiveFallback: true}
	if !GuidedPlanWithinCausalEligibility(plan, "tls_fingerprint_specific", "provisional-fast") {
		t.Fatal("mandatory narrower family must always be allowed")
	}
	if after := ddiCounterValue(t, observability.MetricDiscoveryProfileOutsideCausalEligibility); after != 0 {
		t.Fatalf("allowed branches must not increment counter, got %d", after)
	}
}

func TestHardGateProducer_DDIDisabledExhaustiveFallback(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileDisabledExhaustiveFallback, func() {
		ExhaustiveFallbackEnabled(GuidedSearchPlan{Baseline: []string{"1.1.1.1"}, Ordered: []string{"1.1.1.1"}})
	})
}

func TestHardGateProducer_DDISkippedTargetValidation(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileSkippedTargetValidation, func() {
		GuidedRunTargetValidated(false)
	})
}

func TestHardGateProducer_DDIDirectProductionWrite(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileDirectProductionWrite, func() {
		ProfileProductionWrite(false)
	})
}

func TestHardGateProducer_DDIAllowedSNIDirectPromotion(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileAllowedSNIDirectPromotion, func() {
		PromoteViaSNI(false)
	})
}

func TestHardGateProducer_DDIThresholdOutOfBudget(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileThresholdOutOfBudget, func() {
		CheckHintThreshold(SearchHint{Candidate: "1.1.1.1", Provenance: "p", Threshold: 100}, 50)
	})
}

func TestHardGateProducer_DDICaptureGateBypass(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileCaptureGateBypass, func() {
		PromotionCaptureGate(false)
	})
}

func TestHardGateProducer_DDICrossServiceAction(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileCrossServiceAction, func() {
		now := time.Now()
		target := monitorScope()
		target.ServiceProfileID = "other-svc"
		ProfileActionScope(ddiProfile(t, now), target)
	})
}

func TestHardGateProducer_DDIFalsePass(t *testing.T) {
	assertDDIInc(t, observability.MetricDiscoveryProfileFalsePass, func() {
		b := IssueBundle{
			IssueID:  "i",
			Redacted: true,
			Comparison: CausalABComparison{
				WithoutProfile:     SearchSavingsReport{BaselineProbes: 10},
				WithProfile:        SearchSavingsReport{GuidedProbes: 5},
				StaleSuppressed:    true,
				ConflictSuppressed: true,
				SameControls:       true,
				FalsePromotion:     true,
			},
		}
		PublishIssue(b)
	})
}
