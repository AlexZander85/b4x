package runtimecontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
)

type fakeRuntime struct {
	readiness    RuntimeReadiness
	readinessErr error
	canary       CanaryOutcome
	canaryErr    error
	promoteErr   error
	drainErr     error
	resumeErr    error
	rollbackErr  error
	readinessN   int
	canaryN      int
	promoteN     int
	drainN       int
	resumeN      int
	rollbackN    int
	closeN       int
}

func (f *fakeRuntime) Readiness(context.Context) (RuntimeReadiness, error) {
	f.readinessN++
	return f.readiness, f.readinessErr
}
func (f *fakeRuntime) Canary(context.Context, CanarySpec) (CanaryOutcome, error) {
	f.canaryN++
	return f.canary, f.canaryErr
}
func (f *fakeRuntime) Promote(context.Context) error          { f.promoteN++; return f.promoteErr }
func (f *fakeRuntime) Drain(context.Context) error            { f.drainN++; return f.drainErr }
func (f *fakeRuntime) Resume(context.Context) error           { f.resumeN++; return f.resumeErr }
func (f *fakeRuntime) Rollback(context.Context, string) error { f.rollbackN++; return f.rollbackErr }
func (f *fakeRuntime) Close(context.Context) error            { f.closeN++; return nil }

type fakeBuilder struct {
	runtime Runtime
	err     error
	buildN  int
}

func (b *fakeBuilder) Build(context.Context, *config.Config, GenerationMeta) (Runtime, error) {
	b.buildN++
	return b.runtime, b.err
}

func validCanary() CanarySpec {
	return CanarySpec{
		ClientGroup:    "mac:aa:bb:cc:dd:ee:ff",
		SetID:          "youtube-api",
		Protocol:       "tcp",
		NewFlowPercent: 25,
		Duration:       2 * time.Second,
		MinSamples:     2,
		Stop:           CanaryStopConditions{MaxFailures: 1, StopOnCaptureIncomplete: true},
	}
}

func validOutcome() CanaryOutcome {
	return CanaryOutcome{Passed: true, Samples: 2, StartedAt: time.Unix(10, 0), CompletedAt: time.Unix(11, 0)}
}

func testConfig(flag bool) *config.Config {
	cfg := config.NewConfig()
	cfg.System.Classifier.Flags.ClassifierV2Enabled = flag
	cfg.System.Classifier.Flags.TransactionalApplyEnabled = true
	return &cfg
}

func testManager(t *testing.T, builder *fakeBuilder, opts Options) (*Manager, *fakeRuntime, *clock.FixedClock, *MemoryLastGoodStore) {
	t.Helper()
	clk := clock.NewFixed(time.Unix(100, 0))
	store := &MemoryLastGoodStore{}
	opts.Enabled = true
	opts.Clock = clk
	opts.LastGood = store
	manager, err := NewManager(builder, opts)
	if err != nil {
		t.Fatal(err)
	}
	initial := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	if err := manager.InstallInitial(testConfig(false), initial); err != nil {
		t.Fatal(err)
	}
	return manager, initial, clk, store
}

func TestApplyValidationFailureLeavesPreviousGeneration(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, _, _, _ := testManager(t, builder, Options{})
	before, ok := manager.Active()
	if !ok {
		t.Fatal("initial generation is not active")
	}
	bad := testConfig(false)
	bad.System.Classifier.SchemaVersion = 999
	_, err := manager.Apply(context.Background(), bad, ApplyRequest{Canary: validCanary()})
	if err == nil || !errors.Is(err, &config.ValidationError{}) {
		var tx *TransactionError
		if !errors.As(err, &tx) || tx.Stage != StageValidate {
			t.Fatalf("validation error=%v", err)
		}
	}
	after, _ := manager.Active()
	if after.ID != before.ID || builder.buildN != 0 {
		t.Fatalf("validation changed active generation=%+v builds=%d", after, builder.buildN)
	}
}

func TestApplyReadinessFailureCleansCandidateAndKeepsPrevious(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: false, Reason: "queue owner mismatch"}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, _, _, _ := testManager(t, builder, Options{})
	before, _ := manager.Active()
	result, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StageReadiness {
		t.Fatalf("error=%v", err)
	}
	if result.Readiness.Ready || next.rollbackN != 1 || next.closeN != 1 {
		t.Fatalf("readiness=%+v rollback=%d close=%d", result.Readiness, next.rollbackN, next.closeN)
	}
	after, _ := manager.Active()
	if after.ID != before.ID {
		t.Fatalf("previous generation was replaced: before=%s after=%s", before.ID, after.ID)
	}
}

func TestPartialCanaryFailureRecordsCooldown(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: CanaryOutcome{Passed: false, Samples: 2, Failures: 2, StopReason: "body threshold failed"}}
	builder := &fakeBuilder{runtime: next}
	manager, _, clk, _ := testManager(t, builder, Options{Cooldown: time.Minute})
	candidate := testConfig(true)
	_, err := manager.Apply(context.Background(), candidate, ApplyRequest{Canary: validCanary()})
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StageCanary || next.rollbackN != 1 {
		t.Fatalf("error=%v rollback=%d", err, next.rollbackN)
	}
	_, err = manager.Apply(context.Background(), candidate, ApplyRequest{Canary: validCanary()})
	if !errors.Is(err, ErrCooldown) {
		t.Fatalf("repeat candidate was not cooled down: %v", err)
	}
	clk.Advance(time.Minute)
	if err := manager.cooldown.Check(CooldownKey{SetID: "youtube-api", ClientGroup: validCanary().ClientGroup, Protocol: "tcp", CandidateGeneration: makeGenerationMeta(candidate.Clone(), clk.Now()).ID}); err != nil {
		t.Fatalf("cooldown did not expire: %v", err)
	}
}

func TestSuccessfulApplyPersistsMetadataAndDrainsPrevious(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, previous, _, store := testManager(t, builder, Options{B4Version: "test-build"})
	result, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	if err != nil {
		t.Fatal(err)
	}
	active, ok := manager.Active()
	if !ok || active.ID != result.Generation.ID || previous.drainN != 1 || next.rollbackN != 0 {
		t.Fatalf("active=%+v previous drain=%d candidate rollback=%d", active, previous.drainN, next.rollbackN)
	}
	if record, err := manager.LastGood(); err != nil || record == nil || record.GenerationHash != active.ID || record.B4Version != "test-build" || len(record.SetIDs) != 0 {
		t.Fatalf("last-good=%+v err=%v", record, err)
	}
	if len(manager.History()) == 0 {
		t.Fatal("promotion history is empty")
	}
	if committed, err := store.Load(); err != nil || committed == nil || committed.GenerationHash != active.ID {
		t.Fatalf("store=%+v err=%v", committed, err)
	}
}

func TestCrashDuringPromoteKeepsPreviousGeneration(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, previous, _, _ := testManager(t, builder, Options{BeforePromote: func(GenerationMeta) error { return errors.New("simulated promote crash") }})
	before, _ := manager.Active()
	_, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StagePromote {
		t.Fatalf("error=%v", err)
	}
	after, _ := manager.Active()
	if after.ID != before.ID || previous.drainN != 0 || next.rollbackN != 1 || next.closeN != 1 {
		t.Fatalf("before=%s after=%s old drain=%d new rollback=%d close=%d", before.ID, after.ID, previous.drainN, next.rollbackN, next.closeN)
	}
}

func TestRollbackRestoresPreviousAndCleansCandidate(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, previous, _, store := testManager(t, builder, Options{})
	result, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()})
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := manager.Rollback(context.Background(), "partial canary regression")
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Generation.ID == result.Generation.ID || previous.resumeN != 1 || next.rollbackN != 1 || next.closeN != 1 {
		t.Fatalf("rollback=%+v old resume=%d new rollback=%d close=%d", rolled, previous.resumeN, next.rollbackN, next.closeN)
	}
	active, _ := manager.Active()
	if active.ID != rolled.Generation.ID {
		t.Fatalf("active=%s rollback=%s", active.ID, rolled.Generation.ID)
	}
	record, err := store.Load()
	if err != nil || record == nil || record.GenerationHash != active.ID {
		t.Fatalf("last-good after rollback=%+v err=%v", record, err)
	}
	if len(manager.History()) < 2 {
		t.Fatal("rollback was not retained in bounded history")
	}
}

func TestFileLastGoodStoreDoesNotPersistLiveState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "last-good.json")
	store := &FileLastGoodStore{Path: path}
	record := LastGoodRecord{SchemaVersion: LastGoodSchemaVersion, ConfigHash: "cfg-hash", GenerationHash: "gen-hash", B4Version: "v", Timestamp: time.Unix(1, 0), Validation: ValidationSummary{Valid: true}}
	if err := store.Prepare(record); err != nil {
		t.Fatal(err)
	}
	if loaded, err := store.Load(); err != nil || loaded != nil {
		t.Fatalf("pending record became last-good: %+v err=%v", loaded, err)
	}
	if err := store.Commit(record); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded == nil || loaded.GenerationHash != record.GenerationHash {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "flow") || strings.Contains(string(data), "hint") || strings.Contains(string(data), "raw") {
		t.Fatalf("last-good contains live-state field: %s", data)
	}
}

func FuzzCanaryOutcomeValidation(f *testing.F) {
	f.Add(uint64(2), uint64(0), true)
	f.Add(uint64(1), uint64(2), false)
	spec := validCanary()
	f.Fuzz(func(t *testing.T, samples, failures uint64, passed bool) {
		samples %= MaxCanarySamples + 1
		failures %= MaxCanarySamples + 1
		_ = validateCanaryOutcome(spec, CanaryOutcome{Samples: samples, Failures: failures, Passed: passed})
	})
}

func BenchmarkGenerationFingerprint(b *testing.B) {
	cfg := testConfig(true)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = makeGenerationMeta(cfg, time.Unix(int64(i), 0))
	}
}
