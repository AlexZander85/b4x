package fieldtest

import (
	"testing"

	"github.com/daniellavrushin/b4/validation"
)

// FB-03 chain tests: promotion/canary decision must follow the structured
// gate evaluation (FAIL/BLOCKED/STALE/NOT_RUN reject; only PASS admits).

func gateEval(verdict validation.GateVerdict) *validation.GateEvaluation {
	return &validation.GateEvaluation{Verdict: verdict, Applicable: 1, Scanned: 1}
}

func promotionFixture(eval *validation.GateEvaluation) PromotionInput {
	return PromotionInput{
		Target: CandidateMetrics{
			CandidateID: "cand-1", ComponentID: "youtube-api",
			GoodputBPS: 5e6, ColdStartMS: 100, FirstFrameMS: 200, StallCount: 0, Retries: 0,
			CPU: 20, RAM: 128, ControlsClean: true, EvidenceReady: true,
		},
		Controls:         AuthorizationAudit{},
		RepresentationOK: true,
		RSTOK:            true,
		SafetyHash:       "sha256:deadbeef",
		ConfigGeneration: 7,
		Canary:           CanaryResult{CandidateID: "cand-1", Started: true, Promoted: true},
		GateEvaluation:   eval,
	}
}

// permissiveGate satisfies Eligible() for the promotion fixtures.
func permissiveGate() CandidateGate {
	return CandidateGate{MaxColdStart: 1000, MaxFirstFrame: 1000, MaxStalls: 100, MaxRetries: 100, MaxCPU: 100, MaxRAM: 1024}
}

func TestPromoteRejectedOnHardGateFail(t *testing.T) {
	if v := Promote(promotionFixture(gateEval(validation.GateFail)), permissiveGate()); v != PromotionFail {
		t.Fatalf("verdict=%s, want FAIL", v)
	}
}

func TestPromoteBlockedOnMissingProducers(t *testing.T) {
	for _, verdict := range []validation.GateVerdict{validation.GateBlocked, validation.GateStale, validation.GateNotRun} {
		if v := Promote(promotionFixture(gateEval(verdict)), permissiveGate()); v != PromotionBlocked {
			t.Fatalf("verdict=%s -> %s, want BLOCKED", verdict, v)
		}
	}
}

func TestPromotePassOnHardGatePass(t *testing.T) {
	if v := Promote(promotionFixture(gateEval(validation.GatePass)), permissiveGate()); v != PromotionPass {
		t.Fatalf("verdict=%s, want PASS", v)
	}
}

func TestPromoteWithoutEvaluationBehavesAsBefore(t *testing.T) {
	if v := Promote(promotionFixture(nil), permissiveGate()); v != PromotionPass {
		t.Fatalf("verdict=%s, want PASS (no evaluation wired)", v)
	}
}

func TestCanaryEligibleOnlyOnPass(t *testing.T) {
	if !CanaryEligible(nil) {
		t.Fatal("nil evaluation must be eligible")
	}
	if !CanaryEligible(gateEval(validation.GatePass)) {
		t.Fatal("PASS must be eligible")
	}
	for _, verdict := range []validation.GateVerdict{validation.GateFail, validation.GateBlocked, validation.GateStale, validation.GateNotRun, validation.GateNotApplicable} {
		if CanaryEligible(gateEval(verdict)) {
			t.Fatalf("verdict=%s must NOT be eligible", verdict)
		}
	}
}

func TestControllerRecordsGateEvaluation(t *testing.T) {
	c, err := NewController("http://example.test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.Start("run-1", SessionRequest{ClientID: "client-1"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if session.GateEvaluation != nil {
		t.Fatal("new session must have nil gate evaluation")
	}
	// Record a FAIL evaluation (negative fixture path).
	failEval := validation.EvaluateHardGates(
		validation.ReleaseScope{CSI: true}, nil, "", validation.GenerationSet{},
		map[string]uint64{"unrelated_control_action_total": 2},
		map[string]bool{"unrelated_control_action_total": true},
	)
	if failEval.Verdict != validation.GateFail {
		t.Fatalf("fixture verdict=%s, want FAIL", failEval.Verdict)
	}
	if err := c.RecordGateEvaluation("run-1", failEval); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("run-1")
	if !ok || got.GateEvaluation == nil || got.GateEvaluation.Verdict != validation.GateFail {
		t.Fatalf("recorded evaluation missing: %+v", got.GateEvaluation)
	}
	if len(got.GateEvaluation.Violations) != 1 || got.GateEvaluation.Violations[0].Metric != "unrelated_control_action_total" {
		t.Fatalf("violations=%+v", got.GateEvaluation.Violations)
	}
	// Unknown run must error; stopped run must error.
	if err := c.RecordGateEvaluation("nope", failEval); err == nil {
		t.Fatal("unknown run must error")
	}
	if err := c.Stop("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.RecordGateEvaluation("run-1", failEval); err == nil {
		t.Fatal("stopped run must reject recording")
	}
}

// FB-03 integration: a required applicable zero-tolerance gate whose
// producer is missing must yield BLOCKED end-to-end: canonical registry
// selection -> kind-aware evaluation -> promotion rejection, with no
// committed side effect and a clean stop/cleanup path (v2 §0.6.3).
func TestMissingProducerBlocksPromotionEndToEnd(t *testing.T) {
	scope := validation.ReleaseScope{RSTGSO: true, CSI: true}
	// RST/GSO declares zero-tolerance gates (classifier_layout_parity_fail_total,
	// passive_rst_reconnect_regression_total) whose producers are not part of
	// this fixture; readiness inputs (nfqueue_gso_csum_not_ready_total) and
	// telemetry counters (b4_ppe_self_test_total > 0 is normal) must NOT
	// block promotion (owner decision 2026-08-01).
	counters := map[string]uint64{
		"unrelated_control_action_total": 0,
		"b4_ppe_self_test_total":         3, // telemetry: > 0 is normal operation
	}
	produced := map[string]bool{
		"unrelated_control_action_total": true,
		"b4_ppe_self_test_total":         true,
	}
	eval := validation.EvaluateHardGates(scope, nil, "BLOCKED_TARGET_VALIDATION",
		validation.GenerationSet{}, counters, produced)
	if eval.Verdict != validation.GateBlocked {
		t.Fatalf("verdict=%s, want BLOCKED (missing RST/GSO producers); violations=%d telemetry=%d",
			eval.Verdict, len(eval.Violations), len(eval.Telemetry))
	}
	for _, want := range []validation.GateID{"classifier_layout_parity_fail_total", "passive_rst_reconnect_regression_total"} {
		foundMissing := false
		for _, m := range eval.Missing {
			if m == want {
				foundMissing = true
			}
		}
		if !foundMissing {
			t.Fatalf("missing list %v must include %s", eval.Missing, want)
		}
	}
	// Readiness inputs must NOT appear as missing zero-tolerance gates.
	for _, m := range eval.Missing {
		if m == "nfqueue_gso_csum_not_ready_total" {
			t.Fatalf("readiness input must not be a missing zero-tolerance gate: %s", m)
		}
	}
	// Telemetry must be informational only: reported in Telemetry, never in
	// Violations, and must not suppress the BLOCKED verdict.
	if len(eval.Telemetry) == 0 {
		t.Fatal("telemetry counters must be reported as informational")
	}
	for _, v := range eval.Violations {
		if v.Metric == "b4_ppe_self_test_total" {
			t.Fatalf("telemetry counter must not be a violation: %+v", v)
		}
	}

	// Promotion path: BLOCKED evaluation rejects promotion.
	if v := Promote(promotionFixture(&eval), permissiveGate()); v != PromotionBlocked {
		t.Fatalf("verdict=%s, want PromotionBlocked", v)
	}

	// No committed side effect: a session carrying the blocked evaluation
	// stays clean and stops/cleans up without error.
	c, err := NewController("http://example.test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.Start("run-blocked", SessionRequest{ClientID: "client-1"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if session.GateEvaluation != nil {
		t.Fatalf("new session must have nil gate evaluation: %+v", session)
	}
	if err := c.RecordGateEvaluation("run-blocked", eval); err != nil {
		t.Fatal(err)
	}
	if err := c.Stop("run-blocked"); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("run-blocked")
	if !ok || got.GateEvaluation == nil || got.GateEvaluation.Verdict != validation.GateBlocked {
		t.Fatalf("recorded evaluation must survive stop with BLOCKED verdict: %+v", got)
	}
	// Cleanup: recording after stop must be rejected (session closed).
	if err := c.RecordGateEvaluation("run-blocked", eval); err == nil {
		t.Fatal("stopped run must reject recording")
	}
}

func TestStageReportCarriesGateVerdict(t *testing.T) {
	r := StageReport{Stage: "promotion", Verdict: "fail", SourceAddendumHash: "abc", Requirements: []string{"r1"}, HardGates: []string{"unrelated_control_action_total"}, GateVerdict: validation.GateFail}
	if !r.Valid() {
		t.Fatal("report with gate verdict must be valid")
	}
	if r.GateVerdict != validation.GateFail {
		t.Fatalf("gate verdict=%s", r.GateVerdict)
	}
}
