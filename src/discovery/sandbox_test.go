package discovery

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
)

type fakeSandboxBackend struct {
	mu           sync.Mutex
	apply        int
	cleanup      int
	readiness    QueueReadiness
	readinessErr error
	applyStarted chan struct{}
	applyWait    <-chan struct{}
}

func (f *fakeSandboxBackend) Apply(ctx context.Context, _ SandboxSpec) error {
	f.mu.Lock()
	f.apply++
	started := f.applyStarted
	wait := f.applyWait
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (f *fakeSandboxBackend) Readiness(context.Context, SandboxSpec) (QueueReadiness, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readinessErr != nil {
		return QueueReadiness{}, f.readinessErr
	}
	return f.readiness, nil
}

func (f *fakeSandboxBackend) Cleanup(context.Context, SandboxSpec) error {
	f.mu.Lock()
	f.cleanup++
	f.mu.Unlock()
	return nil
}

func (f *fakeSandboxBackend) cleanupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cleanup
}

func validSandboxSpec(mode SandboxMode, id string, queue uint16, port uint16, flow, processed uint32) SandboxSpec {
	spec := SandboxSpec{ID: id, Mode: mode, QueueStart: queue, QueueThreads: 1, FlowMark: flow, ProcessedMark: processed, OwnerToken: "test-owner"}
	switch mode {
	case SandboxBaselineNone:
		spec.SourcePortMin, spec.SourcePortMax = port, port+9
		spec.ExcludeProduction, spec.ExcludeCandidate = true, true
	case SandboxBaselineProduction:
		spec.ExcludeCandidate = true
	case SandboxCandidate:
		spec.SourcePortMin, spec.SourcePortMax = port, port+9
		spec.ExecutorEnabled, spec.ExcludeProduction = true, true
	}
	return spec
}

func readyBackend() *fakeSandboxBackend {
	return &fakeSandboxBackend{readiness: QueueReadiness{Ready: true, OwnerVerified: true, CheckedAt: time.Unix(1, 0)}}
}

func TestSandboxSpecValidationAndIsolation(t *testing.T) {
	none := validSandboxSpec(SandboxBaselineNone, "none", 100, 40000, 10, 11)
	production := validSandboxSpec(SandboxBaselineProduction, "production", 200, 0, 20, 21)
	candidate := validSandboxSpec(SandboxCandidate, "candidate", 300, 40100, 30, 31)
	for _, spec := range []SandboxSpec{none, production, candidate} {
		if err := spec.Validate(); err != nil {
			t.Fatalf("valid %s rejected: %v", spec.Mode, err)
		}
	}
	if err := ValidateSandboxIsolation(none, production); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSandboxIsolation(production, candidate); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSandboxIsolation(candidate, validSandboxSpec(SandboxCandidate, "collision", 301, 40105, 40, 41)); !errors.Is(err, ErrSandboxPortCollision) {
		t.Fatalf("expected source-port collision, got %v", err)
	}
	if err := ValidateSandboxIsolation(candidate, validSandboxSpec(SandboxCandidate, "collision", 300, 40200, 40, 41)); !errors.Is(err, ErrSandboxQueueCollision) {
		t.Fatalf("expected queue collision, got %v", err)
	}
	if err := ValidateSandboxIsolation(candidate, validSandboxSpec(SandboxCandidate, "collision", 302, 40200, 30, 41)); !errors.Is(err, ErrSandboxMarkCollision) {
		t.Fatalf("expected mark collision, got %v", err)
	}
}

func TestSandboxSpecFromConfigUsesImmutableAndDisjointMarks(t *testing.T) {
	cfg := config.NewConfig()
	cfg.RuntimeGeneration = "generation-1"
	none, err := SandboxSpecFromConfig(&cfg, SandboxBaselineNone, "none", 100, 1, 40000, 40010)
	if err != nil {
		t.Fatal(err)
	}
	production, err := SandboxSpecFromConfig(&cfg, SandboxBaselineProduction, "production", 200, 1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := SandboxSpecFromConfig(&cfg, SandboxCandidate, "candidate", 300, 1, 40100, 40110)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSandboxIsolation(none, production); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSandboxIsolation(production, candidate); err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeGeneration = "changed"
	if none.ConfigGeneration != "generation-1" {
		t.Fatal("sandbox retained mutable config state")
	}
}

func TestSandboxAcquireReadyAndCloseIsIdempotent(t *testing.T) {
	backend := readyBackend()
	store := NewMemorySandboxLeaseStore(4)
	manager := NewSandboxManager(SandboxManagerConfig{Backend: backend, Leases: store, Clock: clock.NewFixed(time.Unix(10, 0)), MaxActive: 2})
	handle, err := manager.Acquire(context.Background(), validSandboxSpec(SandboxCandidate, "candidate", 300, 40000, 30, 31))
	if err != nil {
		t.Fatal(err)
	}
	if handle.ID() != "candidate" || len(manager.Active()) != 1 {
		t.Fatalf("unexpected active sandbox: id=%s active=%+v", handle.ID(), manager.Active())
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(manager.Active()) != 0 || backend.cleanupCount() != 1 {
		t.Fatalf("cleanup was not idempotent: active=%+v cleanup=%d", manager.Active(), backend.cleanupCount())
	}
	leases, err := store.Load(context.Background())
	if err != nil || len(leases) != 0 {
		t.Fatalf("lease was not deleted: leases=%+v err=%v", leases, err)
	}
}

func TestSandboxNotReadyRollsBack(t *testing.T) {
	backend := &fakeSandboxBackend{readiness: QueueReadiness{Ready: false, OwnerVerified: false, Reason: "owner mismatch"}}
	store := NewMemorySandboxLeaseStore(4)
	manager := NewSandboxManager(SandboxManagerConfig{Backend: backend, Leases: store, Clock: clock.NewFixed(time.Unix(10, 0))})
	_, err := manager.Acquire(context.Background(), validSandboxSpec(SandboxCandidate, "candidate", 300, 40000, 30, 31))
	if err == nil || !errors.Is(err, ErrSandboxNotReady) {
		t.Fatalf("expected readiness failure, got %v", err)
	}
	if len(manager.Active()) != 0 || backend.cleanupCount() != 1 {
		t.Fatalf("not-ready sandbox was not rolled back: active=%+v cleanup=%d", manager.Active(), backend.cleanupCount())
	}
}

func TestSandboxCancellationDuringApply(t *testing.T) {
	started := make(chan struct{}, 1)
	wait := make(chan struct{})
	backend := readyBackend()
	backend.applyStarted, backend.applyWait = started, wait
	manager := NewSandboxManager(SandboxManagerConfig{Backend: backend, Leases: NewMemorySandboxLeaseStore(4)})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(ctx, validSandboxSpec(SandboxCandidate, "candidate", 300, 40000, 30, 31))
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled sandbox unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled sandbox did not return")
	}
	if len(manager.Active()) != 0 {
		t.Fatalf("canceled sandbox remained active: %+v", manager.Active())
	}
}

func TestSandboxConcurrentWorkersAndCollision(t *testing.T) {
	backend := readyBackend()
	manager := NewSandboxManager(SandboxManagerConfig{Backend: backend, Leases: NewMemorySandboxLeaseStore(32), MaxActive: 16})
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			spec := validSandboxSpec(SandboxCandidate, fmt.Sprintf("candidate-%d", i), uint16(300+i), uint16(40000+i*20), uint32(100+i*2), uint32(101+i*2))
			if handle, err := manager.Acquire(context.Background(), spec); err == nil {
				successes.Add(1)
				_ = handle.Close(context.Background())
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != 8 || len(manager.Active()) != 0 {
		t.Fatalf("concurrent sandbox lifecycle failed: successes=%d active=%+v", successes.Load(), manager.Active())
	}
}

func TestSandboxReconcileCleansOnlyExplicitlyStaleLease(t *testing.T) {
	backend := readyBackend()
	store := NewMemorySandboxLeaseStore(4)
	first := NewSandboxManager(SandboxManagerConfig{Backend: backend, Leases: store, OwnerToken: "old-owner"})
	handle, err := first.Acquire(context.Background(), validSandboxSpec(SandboxCandidate, "candidate", 300, 40000, 30, 31))
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.readiness.Stale = true
	backend.mu.Unlock()
	second := NewSandboxManager(SandboxManagerConfig{Backend: backend, Leases: store, OwnerToken: "new-owner"})
	report, err := second.Reconcile(context.Background())
	if err != nil || report.Cleaned != 1 || report.Examined != 1 {
		t.Fatalf("stale reconcile failed: report=%+v err=%v", report, err)
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.readiness.Stale = false
	backend.mu.Unlock()
	leases, err := store.Load(context.Background())
	if err != nil || len(leases) != 0 {
		t.Fatalf("stale lease remained after reconcile: leases=%+v err=%v", leases, err)
	}
}

func TestFileSandboxLeaseStoreAtomicRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandboxes.json")
	store := &FileSandboxLeaseStore{Path: path, Max: 2}
	lease := SandboxLease{Spec: validSandboxSpec(SandboxCandidate, "candidate", 300, 40000, 30, 31), State: SandboxReady, CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(2, 0)}
	if err := store.Save(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background())
	if err != nil || len(got) != 1 || got[0].Spec.ID != lease.Spec.ID {
		t.Fatalf("lease round trip failed: got=%+v err=%v", got, err)
	}
	if err := store.Delete(context.Background(), lease.Spec.ID); err != nil {
		t.Fatal(err)
	}
	got, err = store.Load(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("lease delete failed: got=%+v err=%v", got, err)
	}
}

func FuzzSandboxSpecValidation(f *testing.F) {
	f.Add(uint16(300), uint16(40000), uint32(30), uint32(31))
	f.Add(uint16(65535), uint16(1), uint32(0), uint32(1))
	f.Fuzz(func(t *testing.T, queue, port uint16, flow, processed uint32) {
		spec := validSandboxSpec(SandboxCandidate, "candidate", queue, port, flow, processed)
		_ = spec.Validate()
	})
}

func BenchmarkValidateSandboxIsolation(b *testing.B) {
	a := validSandboxSpec(SandboxCandidate, "a", 300, 40000, 30, 31)
	c := validSandboxSpec(SandboxCandidate, "c", 500, 40100, 40, 41)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := ValidateSandboxIsolation(a, c); err != nil {
			b.Fatal(err)
		}
	}
}
