package runtimecontrol

import (
	"context"
	"testing"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
)

type visibilityTestBuilder struct{ runtime Runtime }

func (b visibilityTestBuilder) Build(context.Context, *config.Config, GenerationMeta) (Runtime, error) {
	return b.runtime, nil
}

type visibilityTestRuntime struct {
	canaryN  int
	promoteN int
}

func (r *visibilityTestRuntime) Readiness(context.Context) (RuntimeReadiness, error) {
	return RuntimeReadiness{Ready: true}, nil
}
func (r *visibilityTestRuntime) Canary(context.Context, CanarySpec) (CanaryOutcome, error) {
	r.canaryN++
	return CanaryOutcome{Passed: true}, nil
}
func (r *visibilityTestRuntime) Promote(context.Context) error        { r.promoteN++; return nil }
func (*visibilityTestRuntime) Drain(context.Context) error            { return nil }
func (*visibilityTestRuntime) Resume(context.Context) error           { return nil }
func (*visibilityTestRuntime) Rollback(context.Context, string) error { return nil }
func (*visibilityTestRuntime) Close(context.Context) error            { return nil }

func TestVisibilityGuardedRuntimeBlocksCanaryAndPromotion(t *testing.T) {
	gate := ppe.NewVisibilityGate()
	gate.EnsureRequired("gen", "proof required")
	inner := &visibilityTestRuntime{}
	guard := &visibilityGuardedRuntime{Runtime: inner, gate: gate}
	if _, err := guard.Canary(context.Background(), CanarySpec{}); err == nil {
		t.Fatal("canary was not blocked")
	}
	if err := guard.Promote(context.Background()); err == nil {
		t.Fatal("promotion was not blocked")
	}
	gate.PublishSelfTest(ppe.CaptureVisibilityResult{Verdict: ppe.VerdictPASS, ProductionReady: true})
	if _, err := guard.Canary(context.Background(), CanarySpec{}); err != nil {
		t.Fatal(err)
	}
	if err := guard.Promote(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inner.canaryN != 1 || inner.promoteN != 1 {
		t.Fatalf("inner calls canary=%d promote=%d", inner.canaryN, inner.promoteN)
	}
}
