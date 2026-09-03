package runtimecontrol

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/validation"
)

// FB-03 chain: a non-PASS hard-gate evaluation must reject promotion at
// StagePromote, clean up the candidate (rollback+close), keep the previous
// generation active and retain the failure in bounded history.

func TestApplyHardGateFailureRejectsPromotionAndRollsBack(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, previous, _, _ := testManager(t, builder, Options{
		HardGateCheck: func(GenerationMeta) error {
			return errors.New("hard-gate check failed for generation x: verdict FAIL (1 violations, 0 missing)")
		},
	})
	before, _ := manager.Active()
	_, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StagePromote {
		t.Fatalf("error=%v (want StagePromote)", err)
	}
	if !strings.Contains(err.Error(), "hard-gate") {
		t.Fatalf("error does not identify hard-gate check: %v", err)
	}
	after, _ := manager.Active()
	if after.ID != before.ID {
		t.Fatalf("active generation changed: before=%s after=%s", before.ID, after.ID)
	}
	if previous.drainN != 0 || next.rollbackN != 1 || next.closeN != 1 {
		t.Fatalf("old drain=%d candidate rollback=%d close=%d", previous.drainN, next.rollbackN, next.closeN)
	}
	history := manager.History()
	if len(history) == 0 || history[len(history)-1].Success {
		t.Fatalf("failure not retained in history: %+v", history)
	}
}

func TestApplyHardGateBlockedMissingProducerRejects(t *testing.T) {
	// BLOCKED (missing producers) is a rejection, not PASS (v2 §0.6.3).
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, _, _, _ := testManager(t, builder, Options{
		HardGateCheck: func(GenerationMeta) error {
			eval := validation.EvaluateHardGates(
				validation.ReleaseScope{WARPBase: true}, nil, "", validation.GenerationSet{},
				map[string]uint64{}, map[string]bool{},
			)
			if eval.Verdict != validation.GateBlocked {
				t.Fatalf("expected BLOCKED fixture, got %s", eval.Verdict)
			}
			return errors.New("hard-gate check failed: verdict BLOCKED (0 violations, 36 missing)")
		},
	})
	before, _ := manager.Active()
	_, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StagePromote {
		t.Fatalf("error=%v (want StagePromote)", err)
	}
	after, _ := manager.Active()
	if after.ID != before.ID || next.rollbackN != 1 {
		t.Fatalf("active=%s rollback=%d", after.ID, next.rollbackN)
	}
}

func TestApplyHardGatePassProceedsToPromote(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, previous, _, _ := testManager(t, builder, Options{
		HardGateCheck: func(GenerationMeta) error {
			eval := validation.EvaluateHardGates(
				validation.ReleaseScope{PPE: true, CSI: true}, nil, "", validation.GenerationSet{},
				map[string]uint64{
					"b4_capture_visibility_degrade_total": 0,
					"b4_hold_disabled_visibility_total":   0,
					"b4_ppe_rule_reapply_total":           0,
					"b4_ppe_self_test_total":              0,
					"unrelated_control_action_total":      0,
				},
				map[string]bool{
					"b4_capture_visibility_degrade_total": true,
					"b4_hold_disabled_visibility_total":   true,
					"b4_ppe_rule_reapply_total":           true,
					"b4_ppe_self_test_total":              true,
					"unrelated_control_action_total":      true,
				},
			)
			if eval.Verdict != validation.GatePass {
				t.Fatalf("fixture must PASS, got %s", eval.Verdict)
			}
			return nil
		},
	})
	result, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	if err != nil {
		t.Fatal(err)
	}
	active, _ := manager.Active()
	if active.ID != result.Generation.ID {
		t.Fatalf("candidate was not promoted: active=%s want=%s", active.ID, result.Generation.ID)
	}
	if previous.drainN != 1 || next.rollbackN != 0 {
		t.Fatalf("old drain=%d candidate rollback=%d", previous.drainN, next.rollbackN)
	}
}

func TestPendingPromoteHardGateFailureRejectsAndCleans(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, previous, _, _ := testManager(t, builder, Options{
		HardGateCheck: func(GenerationMeta) error { return errors.New("hard-gate check failed: verdict FAIL (1 violations, 0 missing)") },
	})
	before, _ := manager.Active()
	if _, err := manager.Prepare(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RunCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := manager.PromotePending(context.Background())
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StagePromote {
		t.Fatalf("error=%v (want StagePromote)", err)
	}
	after, _ := manager.Active()
	if after.ID != before.ID {
		t.Fatalf("active generation changed: before=%s after=%s", before.ID, after.ID)
	}
	if previous.drainN != 0 || next.rollbackN != 1 || next.closeN != 1 {
		t.Fatalf("old drain=%d candidate rollback=%d close=%d", previous.drainN, next.rollbackN, next.closeN)
	}
	if _, pending := manager.Pending(); pending {
		t.Fatal("pending candidate survived the rejected promotion")
	}
}
