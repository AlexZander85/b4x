package detector

import (
	"github.com/daniellavrushin/b4/monitor"
	"testing"
	"time"
)

func monitorReq(now time.Time) monitor.MonitorDiagnosticRequest {
	scope := monitor.MonitorScopeKey{ClientScope: monitor.ClientScopeKey{ID: "c", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "n", ConfigGeneration: 1}
	l := monitor.DiagnosticLease{LeaseID: "l", Request: monitor.DiagnosticRequest{IdempotencyKey: "i", Scope: scope, Kind: monitor.DiagnosticQuick}, AcquiredAt: now, ExpiresAt: now.Add(time.Minute)}
	return monitor.MonitorDiagnosticRequest{RequestID: "r", Lease: l, Overlay: monitor.TargetPlanOverlay{Scope: scope, ResolutionSnapshotID: "res", TargetHashes: []string{"t"}, ControlHashes: []string{"ctrl"}, VisibilitySnapshotID: "vis", ConfigGeneration: 1}, RequestedAt: now, ResolutionFresh: true, VisibilityFresh: true}
}

func TestCompilePlanPreservesControlsAndIsDeterministic(t *testing.T) {
	now := time.Unix(10000, 0)
	a := CompileDiagnosticTargetPlan(UserTargetSelection{SelectionID: "s", ServiceProfileID: "svc", ComponentID: "web", Domains: []string{"example.com"}}, monitorReq(now), now)
	if !a.Accepted || !a.Plan.Valid() {
		t.Fatalf("plan rejected: %+v", a)
	}
	b := CompileDiagnosticTargetPlan(UserTargetSelection{SelectionID: "s", ServiceProfileID: "svc", ComponentID: "web", Domains: []string{"example.com"}}, monitorReq(now), now)
	if a.Plan.PlanID != b.Plan.PlanID || a.PreservedControls < 2 {
		t.Fatalf("non-deterministic or controls lost: %+v", a)
	}
}

func TestCompilePlanRejectsExpiredOverlay(t *testing.T) {
	now := time.Unix(10000, 0)
	r := monitorReq(now)
	r.VisibilityFresh = false
	x := CompileDiagnosticTargetPlan(UserTargetSelection{SelectionID: "s", ServiceProfileID: "svc", ComponentID: "web", Domains: []string{"x"}}, r, now)
	if x.Accepted {
		t.Fatal("expired/stale overlay accepted")
	}
}
