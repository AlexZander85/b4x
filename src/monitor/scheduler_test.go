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
