package detector

import (
	"testing"
	"time"
)

func TestHandoffGuardIsIdempotentAndGenerationSafe(t *testing.T) {
	now := time.Unix(19000, 0)
	scope := monitorScopeForDetector()
	r := MonitorDiagnosticResult{ResultID: "res", AssessmentID: "a", RequestID: "q", Scope: scope, ConfigGeneration: 1, Status: ResultAccepted, DeliveredAt: now}
	g := NewHandoffGuard()
	if ok, err := g.Deliver(r, "a", "q", scope); err != nil || !ok {
		t.Fatal(err)
	}
	if ok, err := g.Deliver(r, "a", "q", scope); err != nil || !ok {
		t.Fatal("idempotent duplicate rejected")
	}
	other := scope
	other.ConfigGeneration = 2
	if ok, err := g.Deliver(r, "a", "q", other); err == nil || ok {
		t.Fatal("generation mismatch accepted")
	}
}

func TestCheckpointAndCapacityNeverClaimProduction(t *testing.T) {
	now := time.Unix(19000, 0)
	scope := monitorScopeForDetector()
	c := DeepCheckpoint{RunID: "run", Scope: scope, ConfigGeneration: 1, NetworkContextID: "wan", SavedAt: now}
	if !c.Compatible(scope, now.Add(time.Minute)) {
		t.Fatal("compatible checkpoint rejected")
	}
	if c.Compatible(scope, now.Add(time.Hour)) {
		t.Fatal("expired checkpoint reused")
	}
	p := CalibrateCapacity(10, time.Second, now)
	if p.Calibrated {
		t.Fatal("unsafe capacity calibrated")
	}
	if (ABDReleaseGate{DetectorTestsPassed: true, MonitorAdapterReady: true, ClientResolutionReady: true, MultiVantageReady: true, CapacitySafe: true, DirectApplyDisabled: true}).Verdict() == "ABD_PRODUCTION_READY" {
		t.Fatal("external validation bypassed")
	}
}
