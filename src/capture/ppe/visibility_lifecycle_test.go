package ppe

import (
	"context"
	"errors"
	"testing"
)

type visibilityLifecycleFixture struct {
	desired DesiredState
	assert  error
}

func (f *visibilityLifecycleFixture) Current() (DesiredState, bool) { return f.desired, true }
func (f *visibilityLifecycleFixture) Assert(context.Context) error  { return f.assert }
func (f *visibilityLifecycleFixture) Reapply(context.Context) (TransactionResult, error) {
	f.assert = nil
	return TransactionResult{}, nil
}

func TestVisibilityLifecycleDegradesAndRequiresRevalidation(t *testing.T) {
	gate := NewVisibilityGate()
	fixture := &visibilityLifecycleFixture{desired: DesiredState{Generation: "gen-1", Policy: "exclude"}, assert: errors.New("missing jump")}
	manager := WrapLifecycleWithVisibility(fixture, gate)
	_, _ = manager.Current()
	gate.PublishSelfTest(CaptureVisibilityResult{Verdict: VerdictPASS, ProductionReady: true})
	if err := manager.Assert(context.Background()); err == nil {
		t.Fatal("missing rule was not reported")
	}
	if gate.Snapshot().Mode != VisibilityIncomplete {
		t.Fatalf("mode=%s", gate.Snapshot().Mode)
	}
	if _, err := manager.Reapply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gate.Snapshot().Mode != VisibilityUnknown || gate.Decision(VisibilityFeatureHoldReplay).Allowed {
		t.Fatalf("reapply incorrectly restored proof: %+v", gate.Snapshot())
	}
}
