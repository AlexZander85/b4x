package handler

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/nfq"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/runtimecontrol"
	"github.com/daniellavrushin/b4/tables"
)

var (
	runtimeTopologyMu sync.Mutex
	globalGSOTopology *nfq.GSOQueueTopology
)

// ApplyRuntimeControlTopology performs a double-buffered listener/rule switch.
// The candidate queue start is assigned internally and persisted only after the
// new topology is ready and the old topology has drained.
func (api *API) ApplyRuntimeControlTopology(ctx context.Context, active, candidate *config.Config, meta runtimecontrol.GenerationMeta) (err error) {
	fromMode, toMode := config.GSOModeOff, config.GSOModeOff
	if active != nil {
		fromMode = active.System.Classifier.Runtime.Capture.NFQueue.GSOMode
	}
	if candidate != nil {
		toMode = candidate.System.Classifier.Runtime.Capture.NFQueue.GSOMode
	}
	defer func() {
		result := "success"
		if err != nil {
			result = "rollback"
		}
		observability.Default().Metrics.Inc(observability.MetricNFQueueGSOTransition, map[string]string{"from": fromMode, "to": toMode, "result": result}, 1)
	}()
	if api == nil || active == nil || candidate == nil {
		return errors.New("runtime topology apply requires active and candidate configs")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runtimeTopologyMu.Lock()
	defer runtimeTopologyMu.Unlock()
	if globalPool == nil {
		return errors.New("active NFQUEUE pool is unavailable")
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("candidate validation failed: %w", err)
	}
	if err := runtimeControlDiffAllowed(active, candidate); err != nil {
		return err
	}
	plan, err := capture.PlanGSOTopologyTransition(active, candidate)
	if err != nil {
		return err
	}
	actual := candidate.Clone()
	actual.Queue.StartNum = int(plan.Production.Start)
	actual.Queue.Threads = int(plan.Production.Threads)
	actual.ConfigPath = active.ConfigPath
	if err := actual.Validate(); err != nil {
		return fmt.Errorf("allocated topology config failed validation: %w", err)
	}
	prepared, err := actual.PrepareSave(actual.ConfigPath)
	if err != nil {
		return fmt.Errorf("prepare topology config persistence: %w", err)
	}
	defer prepared.Abort()

	backend := &liveGSOTopologyBackend{
		api: api, active: active.Clone(), candidate: actual, plan: plan, meta: cloneTopologyGenerationMeta(meta),
		previousPool: globalPool, previousTopology: globalGSOTopology, prepared: prepared,
	}
	tx, err := runtimecontrol.NewTopologyTransaction(backend)
	if err != nil {
		return err
	}
	if _, err := tx.Apply(ctx, plan); err != nil {
		return err
	}
	return nil
}

// cloneTopologyGenerationMeta keeps the handler independent of unexported clone helpers.
func cloneTopologyGenerationMeta(m runtimecontrol.GenerationMeta) runtimecontrol.GenerationMeta {
	m.StrategyIDs = append([]string(nil), m.StrategyIDs...)
	m.SetIDs = append([]string(nil), m.SetIDs...)
	m.Validation.Errors = append([]string(nil), m.Validation.Errors...)
	return m
}

type liveGSOTopologyBackend struct {
	api              *API
	active           *config.Config
	candidate        *config.Config
	plan             capture.GSOTopologyPlan
	meta             runtimecontrol.GenerationMeta
	previousPool     *nfq.Pool
	previousTopology *nfq.GSOQueueTopology
	newTopology      *nfq.GSOQueueTopology
	ruleTx           *tables.GSOQueueRuleTransaction
	prepared         *config.PreparedConfigSave
	drained          bool
	committed        bool
}

func (b *liveGSOTopologyBackend) Validate(ctx context.Context, plan capture.GSOTopologyPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if b.candidate.System.Tables.SkipSetup {
		return errors.New("transactional NFQUEUE topology requires B4-owned firewall rules")
	}
	if b.candidate.Queue.Mode != "" && b.candidate.Queue.Mode != "nfqueue" {
		return errors.New("transactional GSO topology requires NFQUEUE mode")
	}
	return nil
}
func (b *liveGSOTopologyBackend) Reserve(ctx context.Context, plan capture.GSOTopologyPlan) error {
	previous, err := capture.PlanGSOTopology(b.active)
	if err != nil {
		return err
	}
	b.ruleTx, err = tables.PrepareGSOQueueRuleTransaction(ctx, b.active, previous.Production, plan.Production)
	if err != nil {
		return fmt.Errorf("prepare queue rule switch: %w", err)
	}
	b.newTopology, err = nfq.NewGSOQueueTopology(b.candidate, plan)
	return err
}
func (b *liveGSOTopologyBackend) StartSecondary(ctx context.Context, _ capture.GSOTopologyPlan) error {
	return b.newTopology.StartSecondary(ctx)
}
func readinessFromReport(report capture.QueueReadinessReport) runtimecontrol.RuntimeReadiness {
	reason := "queue owner verified"
	if len(report.Errors) > 0 {
		reason = report.Errors[0]
	} else if len(report.MissingQueues) > 0 {
		reason = fmt.Sprintf("missing queues: %v", report.MissingQueues)
	} else if len(report.OwnerMismatches) > 0 {
		reason = fmt.Sprintf("owner mismatch: %v", report.OwnerMismatches)
	}
	return runtimecontrol.RuntimeReadiness{Ready: report.Ready, CheckedAt: report.CheckedAt, Reason: reason, QueueDrops: report.QueueDrops, UserDrops: report.UserDrops}
}
func (b *liveGSOTopologyBackend) SecondaryReadiness(_ context.Context, plan capture.GSOTopologyPlan) (runtimecontrol.RuntimeReadiness, error) {
	if !plan.Normalizer.Enabled {
		return runtimecontrol.RuntimeReadiness{Ready: true, Reason: "normalizer not required"}, nil
	}
	return readinessFromReport(b.newTopology.Readiness(capture.TopologyQueueNormalizer)), nil
}
func (b *liveGSOTopologyBackend) StartClassifier(ctx context.Context, _ capture.GSOTopologyPlan) error {
	return b.newTopology.StartClassifier(ctx)
}
func (b *liveGSOTopologyBackend) ClassifierReadiness(_ context.Context, _ capture.GSOTopologyPlan) (runtimecontrol.RuntimeReadiness, error) {
	return readinessFromReport(b.newTopology.Readiness(capture.TopologyQueueProduction)), nil
}
func (b *liveGSOTopologyBackend) SwitchRules(ctx context.Context, _ capture.GSOTopologyPlan) error {
	if err := b.ruleTx.Switch(ctx); err != nil {
		return err
	}
	globalPool = b.newTopology.Primary()
	globalGSOTopology = b.newTopology
	return nil
}
func (b *liveGSOTopologyBackend) DrainPrevious(_ context.Context, _ capture.GSOTopologyPlan) error {
	if b.previousPool != nil {
		b.previousPool.Stop()
	}
	if b.previousTopology != nil {
		b.previousTopology.Close()
	}
	b.drained = true
	return nil
}
func (b *liveGSOTopologyBackend) CommitGeneration(_ context.Context, _ capture.GSOTopologyPlan) error {
	if err := b.prepared.Commit(); err != nil {
		return fmt.Errorf("commit topology config: %w", err)
	}
	b.api.cfgPtr.Store(b.candidate)
	if routingSyncFunc != nil {
		routingSyncFunc(b.candidate)
	}
	b.committed = true
	return nil
}
func (b *liveGSOTopologyBackend) RestorePreviousRules(ctx context.Context) error {
	if b.ruleTx == nil {
		return nil
	}
	if b.drained {
		previousPlan, err := capture.PlanGSOTopology(b.active)
		if err != nil {
			return err
		}
		replacement, err := nfq.NewGSOQueueTopology(b.active, previousPlan)
		if err != nil {
			return err
		}
		if err := replacement.StartSecondary(ctx); err != nil {
			replacement.Close()
			return err
		}
		if err := replacement.StartClassifier(ctx); err != nil {
			replacement.Close()
			return err
		}
		b.previousTopology = replacement
		b.previousPool = replacement.Primary()
	}
	if err := b.ruleTx.Rollback(ctx); err != nil {
		return err
	}
	globalPool = b.previousPool
	globalGSOTopology = b.previousTopology
	return nil
}
func (b *liveGSOTopologyBackend) ReleaseHeldUnchanged(context.Context) error {
	if b.newTopology != nil {
		b.newTopology.ReleaseHeldUnchanged("topology-rollback")
	}
	return nil
}
func (b *liveGSOTopologyBackend) InvalidateGSOTokens(context.Context) error {
	if b.newTopology != nil {
		b.newTopology.InvalidateTokens()
	}
	return nil
}
func (b *liveGSOTopologyBackend) ClearOwnedTransientState(context.Context) error { return nil }
func (b *liveGSOTopologyBackend) RestoreLastGoodGeneration(context.Context) error {
	b.api.cfgPtr.Store(b.active)
	if routingSyncFunc != nil {
		routingSyncFunc(b.active)
	}
	return nil
}
func (b *liveGSOTopologyBackend) CloseNewTopology(context.Context) error {
	if !b.committed && b.newTopology != nil {
		b.newTopology.Close()
	}
	return nil
}
