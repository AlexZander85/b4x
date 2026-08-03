package runtimecontrol

import (
	"context"
	"errors"
	"testing"
	"time"
)

// blockingRuntime is a fakeRuntime whose Canary blocks until canaryRelease is
// closed (or the context is cancelled), mimicking a long-lived canary that
// would previously pin the manager mutex for the full MaxCanaryDuration.
type blockingRuntime struct {
	fakeRuntime
	canaryStart   chan struct{}
	canaryRelease chan struct{}
}

func (b *blockingRuntime) Canary(ctx context.Context, spec CanarySpec) (CanaryOutcome, error) {
	b.canaryN++
	close(b.canaryStart)
	select {
	case <-b.canaryRelease:
	case <-ctx.Done():
		return CanaryOutcome{}, ctx.Err()
	}
	return b.canary, b.canaryErr
}

// TestStatusAndRollbackDoNotBlockDuringCanary pins the FB-08 invariant: while
// a canary is in flight (up to MaxCanaryDuration), status reads, rollback of
// the active generation, abort attempts and concurrent applies must all
// return quickly instead of waiting for the canary to finish.
func TestStatusAndRollbackDoNotBlockDuringCanary(t *testing.T) {
	first := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: first}
	manager, _, _, _ := testManager(t, builder, Options{})
	initialMeta, _ := manager.Active()
	if _, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()}); err != nil {
		t.Fatal(err)
	}

	blocked := &blockingRuntime{
		fakeRuntime:   fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()},
		canaryStart:   make(chan struct{}),
		canaryRelease: make(chan struct{}),
	}
	builder.runtime = blocked
	applied := make(chan struct{})
	go func() {
		defer close(applied)
		_, _ = manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	}()
	select {
	case <-blocked.canaryStart:
	case <-time.After(5 * time.Second):
		t.Fatal("canary did not start")
	}

	// Status-family calls stay responsive while the canary runs.
	if _, ok := manager.Active(); !ok {
		t.Fatal("no active generation")
	}
	if _, err := manager.LastGood(); err != nil {
		t.Fatalf("last-good: %v", err)
	}

	// Rollback of the active generation must not wait for the canary.
	start := time.Now()
	rolled, err := manager.Rollback(context.Background(), "operator override during canary")
	if err != nil {
		t.Fatalf("rollback blocked or failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("rollback blocked until canary end: %v", elapsed)
	}
	if rolled.Generation.ID != initialMeta.ID {
		t.Fatalf("rollback generation=%s want %s", rolled.Generation.ID, initialMeta.ID)
	}
	activeAfterRollback, _ := manager.Active()
	if activeAfterRollback.ID != initialMeta.ID {
		t.Fatalf("active after rollback=%s want %s", activeAfterRollback.ID, initialMeta.ID)
	}

	// AbortPending of the in-flight canary fails fast with BUSY.
	start = time.Now()
	if err := manager.AbortPending(context.Background(), "cancel"); !errors.Is(err, ErrPendingBusy) {
		t.Fatalf("abort=%v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("abort blocked: %v", elapsed)
	}

	// A concurrent Apply fails fast with ErrPendingExists.
	start = time.Now()
	if _, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()}); !errors.Is(err, ErrPendingExists) {
		t.Fatalf("concurrent apply=%v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("concurrent apply blocked: %v", elapsed)
	}

	close(blocked.canaryRelease)
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("apply did not finish after canary release")
	}
}

// TestCloseDoesNotStallOnActiveCanary pins the FB-08 shutdown invariant:
// Close must not wait for the full MaxCanaryDuration when a canary is still
// running; it waits at most pendingCanaryCloseGrace and then forcibly tears
// the candidate down.
func TestCloseDoesNotStallOnActiveCanary(t *testing.T) {
	blocked := &blockingRuntime{
		fakeRuntime:   fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()},
		canaryStart:   make(chan struct{}),
		canaryRelease: make(chan struct{}),
	}
	builder := &fakeBuilder{runtime: blocked}
	manager, _, _, _ := testManager(t, builder, Options{})
	applied := make(chan struct{})
	go func() {
		defer close(applied)
		_, _ = manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	}()
	select {
	case <-blocked.canaryStart:
	case <-time.After(5 * time.Second):
		t.Fatal("canary did not start")
	}

	start := time.Now()
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= pendingCanaryCloseGrace+time.Second {
		t.Fatalf("close waited %v for the canary", elapsed)
	}
	if blocked.rollbackN != 1 || blocked.closeN != 1 {
		t.Fatalf("candidate rollback=%d close=%d", blocked.rollbackN, blocked.closeN)
	}

	// The stale Apply caller must surface ErrNoPending, not hang or panic.
	close(blocked.canaryRelease)
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("apply goroutine leaked after close")
	}
}

// TestPromoteAfterAbortRejected pins the stale compare-and-commit invariant:
// a pending generation that was aborted after a successful canary must not be
// promotable.
func TestPromoteAfterAbortRejected(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, _, _, _ := testManager(t, builder, Options{})
	before, _ := manager.Active()
	if _, err := manager.Prepare(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RunCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.AbortPending(context.Background(), "operator override"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PromotePending(context.Background()); !errors.Is(err, ErrNoPending) {
		t.Fatalf("stale promote=%v", err)
	}
	after, _ := manager.Active()
	if after.ID != before.ID {
		t.Fatalf("active changed after stale promote: %s -> %s", before.ID, after.ID)
	}
	if next.rollbackN != 1 || next.closeN != 1 {
		t.Fatalf("candidate rollback=%d close=%d", next.rollbackN, next.closeN)
	}
}
