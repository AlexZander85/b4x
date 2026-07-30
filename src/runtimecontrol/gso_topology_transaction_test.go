package runtimecontrol

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
)

type topologyBackendFixture struct {
	calls  []string
	failAt string
}

func (b *topologyBackendFixture) call(name string) error {
	b.calls = append(b.calls, name)
	if b.failAt == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}
func (b *topologyBackendFixture) Validate(context.Context, capture.GSOTopologyPlan) error {
	return b.call("validate")
}
func (b *topologyBackendFixture) Reserve(context.Context, capture.GSOTopologyPlan) error {
	return b.call("reserve")
}
func (b *topologyBackendFixture) StartSecondary(context.Context, capture.GSOTopologyPlan) error {
	return b.call("start-secondary")
}
func (b *topologyBackendFixture) SecondaryReadiness(context.Context, capture.GSOTopologyPlan) (RuntimeReadiness, error) {
	err := b.call("secondary-ready")
	return RuntimeReadiness{Ready: err == nil, Reason: "secondary not ready"}, err
}
func (b *topologyBackendFixture) StartClassifier(context.Context, capture.GSOTopologyPlan) error {
	return b.call("start-classifier")
}
func (b *topologyBackendFixture) ClassifierReadiness(context.Context, capture.GSOTopologyPlan) (RuntimeReadiness, error) {
	err := b.call("classifier-ready")
	return RuntimeReadiness{Ready: err == nil, Reason: "classifier not ready"}, err
}
func (b *topologyBackendFixture) SwitchRules(context.Context, capture.GSOTopologyPlan) error {
	return b.call("switch-rules")
}
func (b *topologyBackendFixture) DrainPrevious(context.Context, capture.GSOTopologyPlan) error {
	return b.call("drain-previous")
}
func (b *topologyBackendFixture) CommitGeneration(context.Context, capture.GSOTopologyPlan) error {
	return b.call("commit-generation")
}
func (b *topologyBackendFixture) RestorePreviousRules(context.Context) error {
	return b.call("restore-rules")
}
func (b *topologyBackendFixture) ReleaseHeldUnchanged(context.Context) error {
	return b.call("release-held")
}
func (b *topologyBackendFixture) InvalidateGSOTokens(context.Context) error {
	return b.call("invalidate-tokens")
}
func (b *topologyBackendFixture) ClearOwnedTransientState(context.Context) error {
	return b.call("clear-transient")
}
func (b *topologyBackendFixture) RestoreLastGoodGeneration(context.Context) error {
	return b.call("restore-generation")
}
func (b *topologyBackendFixture) CloseNewTopology(context.Context) error { return b.call("close-new") }

func topologyTestPlan(t *testing.T) capture.GSOTopologyPlan {
	t.Helper()
	cfg := config.NewConfig()
	cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = config.GSOModeClassify
	plan, err := capture.PlanGSOTopology(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestTopologyTransactionAppliesNormativeOrder(t *testing.T) {
	backend := &topologyBackendFixture{}
	tx, _ := NewTopologyTransaction(backend)
	report, err := tx.Apply(context.Background(), topologyTestPlan(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"validate", "reserve", "start-secondary", "secondary-ready", "start-classifier", "classifier-ready", "switch-rules", "drain-previous", "commit-generation"}
	if !reflect.DeepEqual(backend.calls, want) {
		t.Fatalf("calls=%v want=%v", backend.calls, want)
	}
	if report.RolledBack || len(report.Completed) != len(want) {
		t.Fatalf("report=%+v", report)
	}
}

func TestTopologyTransactionRollsBackEveryPartialFailure(t *testing.T) {
	phases := []string{"reserve", "start-secondary", "secondary-ready", "start-classifier", "classifier-ready", "switch-rules", "drain-previous", "commit-generation"}
	rollback := []string{"restore-rules", "release-held", "invalidate-tokens", "clear-transient", "restore-generation", "close-new"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			backend := &topologyBackendFixture{failAt: phase}
			tx, _ := NewTopologyTransaction(backend)
			report, err := tx.Apply(context.Background(), topologyTestPlan(t))
			if err == nil || !report.RolledBack {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			if len(backend.calls) < len(rollback) || !reflect.DeepEqual(backend.calls[len(backend.calls)-len(rollback):], rollback) {
				t.Fatalf("rollback order=%v", backend.calls)
			}
		})
	}
}

func TestTopologyTransactionAttemptsAllCompensations(t *testing.T) {
	backend := &topologyBackendFixture{failAt: "restore-rules"}
	// Trigger rollback before switching rules; the injected rollback error must
	// not prevent the remaining cleanup operations.
	backend.failAt = "reserve"
	tx, _ := NewTopologyTransaction(backend)
	_, _ = tx.Apply(context.Background(), topologyTestPlan(t))
	wantTail := []string{"restore-rules", "release-held", "invalidate-tokens", "clear-transient", "restore-generation", "close-new"}
	if !reflect.DeepEqual(backend.calls[len(backend.calls)-len(wantTail):], wantTail) {
		t.Fatalf("calls=%v", backend.calls)
	}
}
