package monitor

import (
	"testing"
	"time"
)

func TestVisibilitySnapshotSuppressesStaleSources(t *testing.T) {
	now := time.Unix(3000, 0)
	store := NewSourceHealthStore()
	store.Publish(SourceHeartbeat{Source: SourceTCPSYN, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second), Visible: true, Sequence: 1})
	v := store.Snapshot(now, []ObservationSource{SourceTCPSYN}, "v1")
	if v.Fresh(now) || v.State != VisibilityPartial {
		t.Fatalf("expected stale visibility: %+v", v)
	}
	dec := NewSuppressorEngine(time.Minute).Evaluate(testScope(), now, v, true, true, false)
	if dec.CanAutoDiagnose || !dec.Suppressed || len(dec.Reasons) != 1 {
		t.Fatalf("expected stale suppressor: %+v", dec)
	}
}

func TestInfrastructureAndGlobalSuppressorsExpire(t *testing.T) {
	now := time.Unix(4000, 0)
	engine := NewSuppressorEngine(time.Second)
	v := VisibilitySnapshot{State: VisibilityComplete, CaptureReady: true, PPEReady: true, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
	if d := engine.Evaluate(testScope(), now, v, false, true, false); d.CanAutoDiagnose {
		t.Fatal("infrastructure must suppress")
	}
	if d := engine.Evaluate(testScope(), now.Add(2*time.Second), v, true, true, false); !d.CanAutoDiagnose {
		t.Fatalf("expired suppressor remained: %+v", d)
	}
	if d := engine.Evaluate(testScope(), now, v, true, true, true); d.CanAutoDiagnose {
		t.Fatal("global outage must suppress")
	}
}
