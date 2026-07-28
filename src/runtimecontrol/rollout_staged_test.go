package runtimecontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func TestStagedPrepareCanaryPromote(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, previous, _, _ := testManager(t, builder, Options{})
	candidate := testConfig(true)
	prepared, err := manager.Prepare(context.Background(), candidate, ApplyRequest{Canary: validCanary()})
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Readiness.Ready || next.promoteN != 0 || previous.drainN != 0 {
		t.Fatalf("prepare mutated runtime: %+v promote=%d drain=%d", prepared, next.promoteN, previous.drainN)
	}
	if _, ok := manager.Pending(); !ok {
		t.Fatal("pending generation was not published")
	}
	outcome, err := manager.RunCanary(context.Background())
	if err != nil || !outcome.Passed || next.canaryN != 1 {
		t.Fatalf("canary=%+v err=%v calls=%d", outcome, err, next.canaryN)
	}
	result, err := manager.PromotePending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Generation.ID != prepared.Generation.ID || next.promoteN != 1 || previous.drainN != 1 {
		t.Fatalf("result=%+v promote=%d drain=%d", result, next.promoteN, previous.drainN)
	}
	if _, ok := manager.Pending(); ok {
		t.Fatal("pending generation survived promote")
	}
}

func TestAbortPendingKeepsActiveGeneration(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, _, _, _ := testManager(t, builder, Options{})
	before, _ := manager.Active()
	if _, err := manager.Prepare(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()}); err != nil {
		t.Fatal(err)
	}
	if err := manager.AbortPending(context.Background(), "operator cancelled"); err != nil {
		t.Fatal(err)
	}
	after, _ := manager.Active()
	if after.ID != before.ID || next.rollbackN != 1 || next.closeN != 1 {
		t.Fatalf("active changed or candidate leaked: before=%s after=%s rollback=%d close=%d", before.ID, after.ID, next.rollbackN, next.closeN)
	}
}

type commitFailStore struct {
	prepared bool
	aborted  bool
}

func (s *commitFailStore) Prepare(LastGoodRecord) error   { s.prepared = true; return nil }
func (s *commitFailStore) Commit(LastGoodRecord) error    { return errors.New("commit failed") }
func (s *commitFailStore) Abort() error                   { s.aborted = true; return nil }
func (s *commitFailStore) Load() (*LastGoodRecord, error) { return nil, nil }

func TestPromoteCommitFailureRestoresPreviousRuntime(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	clk := clock.NewFixed(time.Unix(100, 0))
	store := &commitFailStore{}
	manager, err := NewManager(builder, Options{Enabled: true, Clock: clk, LastGood: store})
	if err != nil {
		t.Fatal(err)
	}
	previous := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	if err := manager.InstallInitial(testConfig(false), previous); err != nil {
		t.Fatal(err)
	}
	before, _ := manager.Active()
	if _, err := manager.Prepare(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RunCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = manager.PromotePending(context.Background())
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StageCommit {
		t.Fatalf("error=%v", err)
	}
	after, _ := manager.Active()
	if after.ID != before.ID || previous.resumeN != 1 || next.rollbackN != 1 || next.closeN != 1 || !store.aborted {
		t.Fatalf("active=%s before=%s resume=%d rollback=%d close=%d abort=%v", after.ID, before.ID, previous.resumeN, next.rollbackN, next.closeN, store.aborted)
	}
}

func TestInstallInitialCommitFailureDoesNotPublishActive(t *testing.T) {
	manager, err := NewManager(&fakeBuilder{}, Options{Enabled: true, Clock: clock.NewFixed(time.Unix(1, 0)), LastGood: &commitFailStore{}})
	if err != nil {
		t.Fatal(err)
	}
	err = manager.InstallInitial(testConfig(false), &fakeRuntime{})
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StageCommit {
		t.Fatalf("error=%v", err)
	}
	if _, ok := manager.Active(); ok {
		t.Fatal("initial runtime was published after persistence failure")
	}
}

func TestRollbackCommitFailureRestoresCurrentRuntime(t *testing.T) {
	next := &fakeRuntime{readiness: RuntimeReadiness{Ready: true}, canary: validOutcome()}
	builder := &fakeBuilder{runtime: next}
	manager, previous, _, _ := testManager(t, builder, Options{})
	if _, err := manager.Apply(context.Background(), testConfig(true), ApplyRequest{Canary: validCanary()}); err != nil {
		t.Fatal(err)
	}
	manager.store = &commitFailStore{}
	before, _ := manager.Active()
	_, err := manager.Rollback(context.Background(), "test commit failure")
	var tx *TransactionError
	if !errors.As(err, &tx) || tx.Stage != StageCommit {
		t.Fatalf("error=%v", err)
	}
	after, _ := manager.Active()
	if after.ID != before.ID || next.resumeN != 1 || previous.resumeN != 1 {
		t.Fatalf("active=%s before=%s current resume=%d previous resume=%d", after.ID, before.ID, next.resumeN, previous.resumeN)
	}
}

func TestValidateCanaryOutcomeRejectsIncompleteFlows(t *testing.T) {
	spec := validCanary()
	outcome := validOutcome()
	outcome.FlowsStarted = 3
	outcome.IncompleteFlows = 1
	outcome.CaptureIncomplete = true
	if err := validateCanaryOutcome(spec, outcome); err == nil {
		t.Fatal("incomplete candidate flow was accepted")
	}
}

func TestCanarySpecRejectsGlobalAndMalformedClientScope(t *testing.T) {
	for _, scope := range []string{"all", "ip:not-an-ip", "mac:not-a-mac"} {
		spec := validCanary()
		spec.ClientGroup = scope
		if err := spec.Validate(); err == nil {
			t.Fatalf("scope %q accepted", scope)
		}
	}
}
