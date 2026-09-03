package action

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/clock"
)

func TestActionTokenACKClosureRequiresCompleteVisibility(t *testing.T) {
	gate := ppe.DefaultVisibilityGate()
	gate.DisableRequirement("test reset")
	defer gate.DisableRequirement("test cleanup")
	store := NewActionTokenStore(ActionTokenStoreConfig{MaxFlows: 4, Timeout: time.Minute, Clock: clock.NewFixed(time.Unix(3500, 0)), Budgets: DefaultActionBudgets()})
	if !store.Claim(tokenRequest(20, 1)).Applied {
		t.Fatal("claim failed")
	}
	gate.EnsureRequired("gen-1", "proof required")
	if store.CloseServerProgress(20) {
		t.Fatal("ACK-dependent closure was allowed without visibility proof")
	}
	gate.PublishSelfTestForGeneration("gen-1", ppe.CaptureVisibilityResult{Verdict: ppe.VerdictPASS, ProductionReady: true})
	if !store.CloseServerProgress(20) {
		t.Fatal("complete visibility did not allow server-progress closure")
	}
}
