package monitor

import (
	"testing"
	"time"
)

func TestCanaryRequiresAndroidMilestoneSeparately(t *testing.T) {
	now := time.Unix(8000, 0)
	a := NewCanarySummaryAdapter()
	scope := testScope()
	base := CanaryObservation{Scope: scope, BindingID: "b", PathID: "p", ObservedAt: now, Success: true}
	base.ObservationID = "1"
	base.Origin = "router"
	base.Milestone = MilestoneRouterBound
	a.Observe(base)
	base.ObservationID = "2"
	base.Milestone = MilestoneTargetHealthy
	a.Observe(base)
	// A router-origin observation must never satisfy the android milestone,
	// even when its milestone field names it (IV-18: no cross-origin
	// escalation from passive/router evidence).
	base.ObservationID = "2b"
	base.Origin = "router"
	base.Milestone = MilestoneAndroidSeen
	a.Observe(base)
	s, _ := a.Snapshot(scope, "b", "p")
	if !s.TargetHealthy || s.AndroidSeen {
		t.Fatalf("router proof leaked android gate: %+v", s)
	}
	base.ObservationID = "3"
	base.Origin = "android"
	base.Milestone = MilestoneAndroidSeen
	a.Observe(base)
	s, _ = a.Snapshot(scope, "b", "p")
	if !s.AndroidSeen {
		t.Fatal("android milestone not recorded")
	}
}

func TestCanaryRollbackIsObservationOnly(t *testing.T) {
	now := time.Unix(8000, 0)
	a := NewCanarySummaryAdapter()
	o := CanaryObservation{ObservationID: "r", Scope: testScope(), BindingID: "b", PathID: "p", Origin: "passive", Milestone: MilestoneRollbackSignal, ObservedAt: now, Success: false}
	if !a.Observe(o) {
		t.Fatal("rollback signal rejected")
	}
	s, _ := a.Snapshot(testScope(), "b", "p")
	if !s.RollbackObserved {
		t.Fatal("rollback signal not exposed")
	}
}
