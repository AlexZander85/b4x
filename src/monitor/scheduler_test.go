package monitor

import (
	"context"
	"testing"
	"time"
)

func TestSchedulerCoalescesAndLeases(t *testing.T) {
	now := time.Unix(5000, 0)
	s := NewDiagnosticScheduler(SchedulerConfig{QuickCapacity: 1, LeaseTTL: time.Second, Backoff: time.Second})
	r := DiagnosticRequest{RequestID: "r1", IdempotencyKey: "k", Scope: testScope(), Kind: DiagnosticQuick, RequestedAt: now}
	if err := s.Enqueue(r, now); err != nil {
		t.Fatal(err)
	}
	r.Reason = "updated"
	if err := s.Enqueue(r, now); err != nil {
		t.Fatal(err)
	}
	if s.Depth(DiagnosticQuick) != 1 {
		t.Fatal("duplicate was not coalesced")
	}
	l, err := s.Acquire(context.Background(), DiagnosticQuick, now)
	if err != nil {
		t.Fatal(err)
	}
	if l.Request.IdempotencyKey != "k" {
		t.Fatal(l)
	}
	if _, err = s.Acquire(context.Background(), DiagnosticQuick, now); err != ErrNoDiagnostic {
		t.Fatalf("running lease duplicated: %v", err)
	}
	if !s.Complete(l.LeaseID, false, now) {
		t.Fatal("failed completion not recorded")
	}
	if _, err = s.Acquire(context.Background(), DiagnosticQuick, now); err != ErrNoDiagnostic {
		t.Fatalf("backoff ignored: %v", err)
	}
	if _, err = s.Acquire(context.Background(), DiagnosticQuick, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerOverloadIsBounded(t *testing.T) {
	s := NewDiagnosticScheduler(SchedulerConfig{QuickCapacity: 1})
	now := time.Now()
	r := DiagnosticRequest{IdempotencyKey: "a", Scope: testScope(), Kind: DiagnosticQuick, RequestedAt: now}
	if s.Enqueue(r, now) != nil {
		t.Fatal("first enqueue failed")
	}
	r.IdempotencyKey = "b"
	if s.Enqueue(r, now) != ErrSchedulerOverloaded {
		t.Fatal("expected overload")
	}
}

// TestSchedulerRunningAndQueuedProjection is the §58 projection evidence:
// Running counts only entries holding an active lease (running_quick/deep),
// Queued counts the waiting remainder (queued_quick/deep), and both add up
// to Depth. A successful completion releases the slot entirely.
func TestSchedulerRunningAndQueuedProjection(t *testing.T) {
	now := time.Unix(6000, 0)
	s := NewDiagnosticScheduler(SchedulerConfig{QuickCapacity: 8, DeepCapacity: 4, LeaseTTL: time.Minute, Backoff: time.Second})
	base := DiagnosticRequest{Scope: testScope(), Kind: DiagnosticQuick, RequestedAt: now}

	for i := 0; i < 3; i++ {
		r := base
		r.IdempotencyKey = "q" + string(rune('a'+i))
		if err := s.Enqueue(r, now); err != nil {
			t.Fatal(err)
		}
	}
	if s.Depth(DiagnosticQuick) != 3 {
		t.Fatalf("depth = %d, want 3", s.Depth(DiagnosticQuick))
	}
	if s.Queued(DiagnosticQuick) != 3 || s.Running(DiagnosticQuick) != 0 {
		t.Fatalf("before acquire: queued=%d running=%d, want 3/0", s.Queued(DiagnosticQuick), s.Running(DiagnosticQuick))
	}

	l, err := s.Acquire(context.Background(), DiagnosticQuick, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Depth(DiagnosticQuick) != 3 {
		t.Fatalf("depth must include the running entry, got %d", s.Depth(DiagnosticQuick))
	}
	if s.Running(DiagnosticQuick) != 1 || s.Queued(DiagnosticQuick) != 2 {
		t.Fatalf("after acquire: running=%d queued=%d, want 1/2", s.Running(DiagnosticQuick), s.Queued(DiagnosticQuick))
	}

	if !s.Complete(l.LeaseID, true, now) {
		t.Fatal("completion not recorded")
	}
	if s.Depth(DiagnosticQuick) != 2 || s.Running(DiagnosticQuick) != 0 || s.Queued(DiagnosticQuick) != 2 {
		t.Fatalf("after success: depth=%d running=%d queued=%d, want 2/0/2", s.Depth(DiagnosticQuick), s.Running(DiagnosticQuick), s.Queued(DiagnosticQuick))
	}

	// A failed completion returns the entry to the queue on backoff: still
	// counted as queued (waiting for the retry slot).
	l2, err := s.Acquire(context.Background(), DiagnosticQuick, now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Complete(l2.LeaseID, false, now) {
		t.Fatal("failed completion not recorded")
	}
	if s.Running(DiagnosticQuick) != 0 || s.Queued(DiagnosticQuick) != 2 {
		t.Fatalf("after failure: running=%d queued=%d, want 0/2", s.Running(DiagnosticQuick), s.Queued(DiagnosticQuick))
	}
}
