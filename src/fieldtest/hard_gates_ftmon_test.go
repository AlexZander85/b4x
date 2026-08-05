package fieldtest

import (
	"testing"

	"github.com/daniellavrushin/b4/validation"
)

// FB-02 fieldtest FT-C: the Field Test Controller calls the canonical
// hard-gate evaluator (Controller.EvaluateHardGates -> fieldtest.EvaluateHardGates
// -> validation.EvaluateHardGates) against observed counters, and the
// recorded verdict drives canary/promotion. Each FT-MON-A..J fixture drives
// the violating branch of one MON hard-gate family through the production
// root and asserts the promotion gate stays fail-closed (FT-MON-A..I) or
// admits on a clean window (FT-MON-J). MON gates are zero-tolerance
// violation counters (addendum v1.0 §84-§92; registry family:mon).

// monScope enables the MON subsystem family for the FT-MON fixtures.
func monScope() validation.ReleaseScope { return validation.ReleaseScope{MON: true} }

// monCounters builds a produced map covering every applicable MON gate with
// zero counts, then raises the named violation counter. produced=true for
// all applicable MON gates so the evaluation can never flip to BLOCKED
// (missing producers) — the fixture must prove the violation branch.
func monCounters(violation string) (map[string]uint64, map[string]bool) {
	required, err := validation.RequiredHardGates(monScope(), nil, "", validation.GenerationSet{})
	if err != nil {
		panic(err)
	}
	counters := make(map[string]uint64, len(required))
	produced := make(map[string]bool, len(required))
	for _, gid := range required {
		name := string(gid)
		produced[name] = true
		if name != violation {
			counters[name] = 0
		}
	}
	if violation != "" {
		counters[violation] = 1
	}
	return counters, produced
}

// ftmonRun starts a controller session, evaluates the MON gates through the
// production root and returns the recorded evaluation.
func ftmonRun(t *testing.T, runID string, violation string) validation.GateEvaluation {
	t.Helper()
	c, err := NewController("http://example.test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.Start(runID, SessionRequest{ClientID: "client-1"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if session.GateEvaluation != nil {
		t.Fatalf("new session must have nil gate evaluation: %+v", session)
	}
	counters, produced := monCounters(violation)
	eval, err := c.EvaluateHardGates(runID, monScope(), nil, "", validation.GenerationSet{}, counters, produced)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get(runID)
	if !ok || got.GateEvaluation == nil {
		t.Fatalf("evaluation must be recorded on the session: %+v", got)
	}
	if got.GateEvaluation.Verdict != eval.Verdict {
		t.Fatalf("session verdict %s != returned verdict %s", got.GateEvaluation.Verdict, eval.Verdict)
	}
	return eval
}

// assertFTMONFail asserts the violating branch verdict: FAIL with exactly
// the target metric in Violations, and promotion rejected.
func assertFTMONFail(t *testing.T, runID, metric string, eval validation.GateEvaluation) {
	t.Helper()
	if eval.Verdict != validation.GateFail {
		t.Fatalf("%s: verdict=%s, want FAIL (violation %s)", runID, eval.Verdict, metric)
	}
	found := false
	for _, v := range eval.Violations {
		if v.Metric == metric {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s: violations=%+v must include %s", runID, eval.Violations, metric)
	}
	if v := Promote(promotionFixture(&eval), permissiveGate()); v != PromotionFail {
		t.Fatalf("%s: promotion verdict=%s, want PromotionFail", runID, v)
	}
}

func TestFTMONALegacyWatchdogBlocksPromotion(t *testing.T) {
	// FT-MON-A: legacy Watchdog compatibility and no-direct-apply — a legacy
	// Watchdog direct apply must fail-closed the promotion gate.
	assertFTMONFail(t, "ft-mon-a", "monitor_legacy_watchdog_direct_apply_total",
		ftmonRun(t, "ft-mon-a", "monitor_legacy_watchdog_direct_apply_total"))
}

func TestFTMONBDemandIntakeCorrelationBlocksPromotion(t *testing.T) {
	// FT-MON-B: demand intake and exact client-resolution correlation —
	// unbounded target intake is a hard-gate violation.
	assertFTMONFail(t, "ft-mon-b", "monitor_unbounded_target_intake_total",
		ftmonRun(t, "ft-mon-b", "monitor_unbounded_target_intake_total"))
}

func TestFTMONCPassiveFlowHealthBlocksPromotion(t *testing.T) {
	// FT-MON-C: passive flow health and control separation — a direct
	// production action from a passive observation violates §84.
	assertFTMONFail(t, "ft-mon-c", "monitor_observation_direct_action_total",
		ftmonRun(t, "ft-mon-c", "monitor_observation_direct_action_total"))
}

func TestFTMONDTemporalRecurrenceBlocksPromotion(t *testing.T) {
	// FT-MON-D: temporal recurrence, decay and recovery — persistence without
	// time separation must block promotion.
	assertFTMONFail(t, "ft-mon-d", "monitor_temporal_persistence_without_time_separation_total",
		ftmonRun(t, "ft-mon-d", "monitor_temporal_persistence_without_time_separation_total"))
}

func TestFTMONEStaleSourceHeartbeatBlocksPromotion(t *testing.T) {
	// FT-MON-E: source health, PPE/capture suppressors — a trigger from a
	// stale source heartbeat violates the source-health gate.
	assertFTMONFail(t, "ft-mon-e", "monitor_trigger_with_stale_source_heartbeat_total",
		ftmonRun(t, "ft-mon-e", "monitor_trigger_with_stale_source_heartbeat_total"))
}

func TestFTMONFFastLaneBudgetBlocksPromotion(t *testing.T) {
	// FT-MON-F: fast lane and trigger budgets — promoting a fast-lane outcome
	// to authoritative violates the fast-lane budget gate.
	assertFTMONFail(t, "ft-mon-f", "monitor_fast_lane_promoted_as_authoritative_total",
		ftmonRun(t, "ft-mon-f", "monitor_fast_lane_promoted_as_authoritative_total"))
}

func TestFTMONGAbdEscalationChainBlocksPromotion(t *testing.T) {
	// FT-MON-G: MON -> ABD quick/deep escalation — an ABD request without a
	// target plan must block promotion.
	assertFTMONFail(t, "ft-mon-g", "monitor_abd_request_without_target_plan_total",
		ftmonRun(t, "ft-mon-g", "monitor_abd_request_without_target_plan_total"))
}

func TestFTMONHDdiDiscoveryChainBlocksPromotion(t *testing.T) {
	// FT-MON-H: ABD -> DDI -> Discovery/WARP recommendation chain — discovery
	// without an authoritative profile violates the chain gate.
	assertFTMONFail(t, "ft-mon-h", "monitor_discovery_without_authoritative_profile_total",
		ftmonRun(t, "ft-mon-h", "monitor_discovery_without_authoritative_profile_total"))
}

func TestFTMONIRestartFaultStorageBlocksPromotion(t *testing.T) {
	// FT-MON-I: restart/fault/storage/privacy — a checkpoint corruption
	// reported as ready must block promotion.
	assertFTMONFail(t, "ft-mon-i", "monitor_checkpoint_corruption_false_ready_total",
		ftmonRun(t, "ft-mon-i", "monitor_checkpoint_corruption_false_ready_total"))
}

func TestFTMONJCleanWindowAdmitsPromotion(t *testing.T) {
	// FT-MON-J: real Keenetic + Android end-to-end — a clean MON window (all
	// applicable MON gates produced and zero) must admit promotion through
	// the same production root used by the failing fixtures.
	c, err := NewController("http://example.test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Start("ft-mon-j", SessionRequest{ClientID: "client-1"}, 3); err != nil {
		t.Fatal(err)
	}
	counters, produced := monCounters("")
	eval, err := c.EvaluateHardGates("ft-mon-j", monScope(), nil, "", validation.GenerationSet{}, counters, produced)
	if err != nil {
		t.Fatal(err)
	}
	if eval.Verdict != validation.GatePass {
		t.Fatalf("FT-MON-J: verdict=%s, want PASS; violations=%+v missing=%v", eval.Verdict, eval.Violations, eval.Missing)
	}
	if !HardGatesPass(monScope(), nil, "", validation.GenerationSet{}, counters, produced) {
		t.Fatal("FT-MON-J: HardGatesPass must admit a clean MON window")
	}
	if !CanaryEligible(&eval) {
		t.Fatal("FT-MON-J: clean evaluation must be canary-eligible")
	}
	if v := Promote(promotionFixture(&eval), permissiveGate()); v != PromotionPass {
		t.Fatalf("FT-MON-J: promotion verdict=%s, want PromotionPass", v)
	}
	got, ok := c.Get("ft-mon-j")
	if !ok || got.GateEvaluation == nil || got.GateEvaluation.Verdict != validation.GatePass {
		t.Fatalf("FT-MON-J: recorded evaluation must survive with PASS: %+v", got)
	}
}
