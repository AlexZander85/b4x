package monitor

import (
	"testing"
	"time"
)

func validMonitorDiagnostic(now time.Time) MonitorDiagnosticRequest {
	l := DiagnosticLease{LeaseID: "lease", Request: DiagnosticRequest{IdempotencyKey: "key", Scope: testScope(), Kind: DiagnosticQuick}, AcquiredAt: now, ExpiresAt: now.Add(time.Minute)}
	return MonitorDiagnosticRequest{RequestID: "req", Lease: l, Overlay: TargetPlanOverlay{Scope: testScope(), ResolutionSnapshotID: "res", TargetHashes: []string{"target"}, VisibilitySnapshotID: "vis", ConfigGeneration: 1}, RequestedAt: now, ResolutionFresh: true, VisibilityFresh: true}
}

func TestABDEscalationPartialCannotBecomeAuthoritative(t *testing.T) {
	now := time.Unix(6000, 0)
	a := NewABDEscalationAdapter()
	run, err := a.Begin(validMonitorDiagnostic(now), now)
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.Complete(ABDResult{RunID: run.RunID, Scope: testScope(), EvidenceRefs: []string{"partial"}, Complete: false, Authoritative: true}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if out.State != RunPartial || out.Authoritative || out.Complete {
		t.Fatalf("partial result leaked authority: %+v", out)
	}
}

func TestABDEscalationRejectsScopeMismatch(t *testing.T) {
	now := time.Unix(6000, 0)
	a := NewABDEscalationAdapter()
	run, err := a.Begin(validMonitorDiagnostic(now), now)
	if err != nil {
		t.Fatal(err)
	}
	other := testScope()
	other.NetworkContextID = "other"
	if _, err = a.Complete(ABDResult{RunID: run.RunID, Scope: other, Complete: true, Authoritative: true, EvidenceRefs: []string{"e"}}, now); err == nil {
		t.Fatal("scope mismatch accepted")
	}
}
