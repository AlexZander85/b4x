package runtimecontrol

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/nfq"
	"github.com/daniellavrushin/b4/tables"
)

// LiveHooks bridges the generic transaction manager to the real process
// configuration. Apply must either make the complete snapshot active and
// durable or leave the previous snapshot active.
type LiveHooks struct {
	Current func() *config.Config
	Apply   func(*config.Config) error
}

func (h LiveHooks) validate() error {
	if h.Current == nil || h.Apply == nil {
		return errors.New("live runtime hooks are incomplete")
	}
	if h.Current() == nil {
		return errors.New("live runtime current config is nil")
	}
	return nil
}

type LiveBuilder struct {
	hooks LiveHooks
}

func NewLiveBuilder(hooks LiveHooks) (*LiveBuilder, error) {
	if err := hooks.validate(); err != nil {
		return nil, err
	}
	return &LiveBuilder{hooks: hooks}, nil
}

func (b *LiveBuilder) Build(ctx context.Context, candidate *config.Config, meta GenerationMeta) (Runtime, error) {
	if b == nil || candidate == nil {
		return nil, ErrInvalidRuntime
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	active := b.hooks.Current()
	if active == nil {
		return nil, errors.New("active config is unavailable")
	}
	if err := validateLiveMarkContract(active); err != nil {
		return nil, err
	}
	if active.Queue.Mode != "" && active.Queue.Mode != "nfqueue" {
		return nil, errors.New("transactional candidate queues require NFQUEUE mode")
	}
	candidateCfg := candidate.Clone()
	offset := candidateCfg.System.Classifier.Runtime.Capture.CandidateQueueOffset
	if offset < 1 {
		return nil, errors.New("candidate queue offset must be positive")
	}
	queueStart := active.Queue.StartNum + active.Queue.Threads + offset
	if queueStart < 0 || queueStart > 65535 {
		return nil, errors.New("candidate queue start is out of range")
	}
	candidateCfg.Queue.StartNum = queueStart
	candidateCfg.Queue.Threads = 1
	candidateCfg.Queue.Mark = active.CanaryInjectedMark()
	candidateCfg.Queue.IsDiscovery = false
	candidateCfg.System.Tables.SkipSetup = true
	pool := nfq.NewCandidatePool(candidateCfg)
	if err := pool.Start(); err != nil {
		pool.Stop()
		return nil, fmt.Errorf("start candidate NFQUEUE pool: %w", err)
	}
	return &liveRuntime{
		cfg: candidate.Clone(), activeAtBuild: active.Clone(), hooks: b.hooks, pool: pool,
		queueStart: queueStart, queueThreads: 1, flowMark: active.CanaryFlowMark(), directMark: active.CanaryDirectMark(),
		injectedMark: active.CanaryInjectedMark(), meta: meta.clone(),
	}, nil
}

func NewActiveRuntime(cfg *config.Config, hooks LiveHooks) (Runtime, error) {
	if cfg == nil {
		return nil, ErrInvalidRuntime
	}
	if err := hooks.validate(); err != nil {
		return nil, err
	}
	return &liveRuntime{cfg: cfg.Clone(), activeAtBuild: cfg.Clone(), hooks: hooks, promoted: true}, nil
}

type liveRuntime struct {
	mu            sync.Mutex
	cfg           *config.Config
	activeAtBuild *config.Config
	hooks         LiveHooks
	pool          *nfq.Pool
	queueStart    int
	queueThreads  int
	flowMark      uint
	directMark    uint
	injectedMark  uint
	meta          GenerationMeta
	steering      *tables.CanarySteeringSpec
	canaryCancel  context.CancelFunc
	canaryDone    chan struct{}
	promoted      bool
	closed        bool
}

func (r *liveRuntime) Readiness(ctx context.Context) (RuntimeReadiness, error) {
	if r == nil || r.cfg == nil {
		return RuntimeReadiness{}, ErrInvalidRuntime
	}
	if err := ctx.Err(); err != nil {
		return RuntimeReadiness{}, err
	}
	queueStart := r.queueStart
	queueThreads := r.queueThreads
	if queueThreads == 0 {
		queueStart = r.cfg.Queue.StartNum
		queueThreads = r.cfg.Queue.Threads
	}
	queues := make([]uint16, 0, queueThreads)
	for i := 0; i < queueThreads; i++ {
		queues = append(queues, uint16(queueStart+i))
	}
	report := capture.CheckQueueReadiness(capture.OSProcFS{}, capture.QueueReadinessSpec{
		QueueNumbers: queues, ExpectedOwnerPortID: uint32(os.Getpid()), RequireOwner: true,
	})
	reason := "queue owner verified"
	if len(report.Errors) > 0 {
		reason = report.Errors[0]
	} else if len(report.MissingQueues) > 0 {
		reason = fmt.Sprintf("missing queues: %v", report.MissingQueues)
	} else if len(report.OwnerMismatches) > 0 {
		reason = fmt.Sprintf("queue owner mismatch: %v", report.OwnerMismatches)
	}
	return RuntimeReadiness{Ready: report.Ready, CheckedAt: report.CheckedAt, Reason: reason, QueueDrops: report.QueueDrops, UserDrops: report.UserDrops}, nil
}

func (r *liveRuntime) Canary(ctx context.Context, spec CanarySpec) (CanaryOutcome, error) {
	if r == nil {
		return CanaryOutcome{}, errors.New("candidate runtime is not allocated")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := spec.Validate(); err != nil {
		return CanaryOutcome{}, err
	}
	if err := ValidateLiveCandidateScope(r.activeAtBuild, r.cfg, spec.SetID); err != nil {
		return CanaryOutcome{}, err
	}
	r.mu.Lock()
	if r.closed || r.pool == nil {
		r.mu.Unlock()
		return CanaryOutcome{}, errors.New("candidate runtime is not allocated")
	}
	if r.canaryCancel != nil {
		r.mu.Unlock()
		return CanaryOutcome{}, ErrPendingBusy
	}
	pool := r.pool
	canaryCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.canaryCancel = cancel
	r.canaryDone = done
	r.mu.Unlock()
	defer func() {
		cancel()
		r.mu.Lock()
		if r.canaryDone == done {
			r.canaryCancel = nil
			r.canaryDone = nil
		}
		close(done)
		r.mu.Unlock()
	}()

	steering := tables.CanarySteeringSpec{
		ClientGroup: spec.ClientGroup, Protocol: spec.Protocol, Percent: spec.NewFlowPercent,
		FlowMark: r.flowMark, DirectMark: r.directMark, InjectedMark: uint(capture.ProcessedMarkFor(r.injectedMark)),
		QueueStart: r.queueStart, QueueThreads: r.queueThreads,
	}
	if err := tables.ApplyCanarySteeringRules(r.activeAtBuild, steering); err != nil {
		return CanaryOutcome{}, fmt.Errorf("apply canary steering: %w", err)
	}
	r.mu.Lock()
	r.steering = &steering
	r.mu.Unlock()
	defer func() {
		tables.ClearCanarySteeringRules(r.activeAtBuild, steering)
		r.mu.Lock()
		r.steering = nil
		r.mu.Unlock()
	}()

	pool.SetCanarySetID(spec.SetID)
	pool.ResetCanary()
	started := time.Now().UTC()
	deadline := time.NewTimer(spec.Duration)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var stopReason string
	for {
		select {
		case <-canaryCtx.Done():
			return CanaryOutcome{}, canaryCtx.Err()
		case <-deadline.C:
			return r.finishCanary(pool, spec, started, stopReason)
		case <-ticker.C:
			snapshot := pool.CanarySnapshot()
			if spec.Stop.MaxFailures > 0 && snapshot.Failures > spec.Stop.MaxFailures {
				stopReason = "maximum failures exceeded"
				return r.finishCanary(pool, spec, started, stopReason)
			}
			if spec.Stop.MaxFailureRate > 0 && snapshot.Samples > 0 && float64(snapshot.Failures)/float64(snapshot.Samples) > spec.Stop.MaxFailureRate {
				stopReason = "maximum failure rate exceeded"
				return r.finishCanary(pool, spec, started, stopReason)
			}
			if spec.Stop.StopOnQueueDrops {
				ready, _ := r.Readiness(canaryCtx)
				if ready.QueueDrops > 0 || ready.UserDrops > 0 {
					stopReason = "queue drops observed"
					return r.finishCanary(pool, spec, started, stopReason)
				}
			}
		}
	}
}

func (r *liveRuntime) finishCanary(pool *nfq.Pool, spec CanarySpec, started time.Time, stopReason string) (CanaryOutcome, error) {
	snapshot := pool.CanarySnapshot()
	readiness, readinessErr := r.Readiness(context.Background())
	failureRate := 0.0
	if snapshot.Samples > 0 {
		failureRate = float64(snapshot.Failures) / float64(snapshot.Samples)
	}
	incompleteFlows := uint64(0)
	if snapshot.FlowsStarted > snapshot.Samples {
		incompleteFlows = snapshot.FlowsStarted - snapshot.Samples
	}
	captureIncomplete := readinessErr != nil || !readiness.Ready || (spec.Stop.StopOnCaptureIncomplete && incompleteFlows > 0)
	passed := stopReason == "" && snapshot.Samples >= spec.MinSamples && !captureIncomplete
	outcome := CanaryOutcome{
		Passed: passed, FlowsStarted: snapshot.FlowsStarted, Samples: snapshot.Samples, IncomingProgress: snapshot.IncomingProgress, IncompleteFlows: incompleteFlows,
		Failures: snapshot.Failures, FailureRate: failureRate,
		QueueDrops: readiness.QueueDrops + readiness.UserDrops, CaptureIncomplete: captureIncomplete,
		StopReason: stopReason, StartedAt: started, CompletedAt: time.Now().UTC(),
	}
	if readinessErr != nil {
		outcome.StopReason = readinessErr.Error()
	}
	if outcome.StopReason == "" && snapshot.Samples < spec.MinSamples {
		outcome.StopReason = fmt.Sprintf("minimum samples not met: got %d need %d", snapshot.Samples, spec.MinSamples)
	}
	if outcome.StopReason == "" && captureIncomplete {
		if incompleteFlows > 0 {
			outcome.StopReason = fmt.Sprintf("candidate flows incomplete: %d", incompleteFlows)
		} else {
			outcome.StopReason = "candidate capture readiness was lost"
		}
	}
	return outcome, nil
}

func (r *liveRuntime) Promote(ctx context.Context) error {
	if r == nil || r.cfg == nil {
		return ErrInvalidRuntime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.hooks.Apply(r.cfg.Clone()); err != nil {
		return err
	}
	r.mu.Lock()
	r.promoted = true
	r.mu.Unlock()
	return r.stopCandidate(ctx)
}

func (r *liveRuntime) Drain(context.Context) error { return nil }

func (r *liveRuntime) Resume(ctx context.Context) error {
	if r == nil || r.cfg == nil {
		return ErrInvalidRuntime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.hooks.Apply(r.cfg.Clone())
}

func (r *liveRuntime) Rollback(ctx context.Context, _ string) error {
	return r.stopCandidate(ctx)
}

func (r *liveRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()
	return r.stopCandidate(ctx)
}

func (r *liveRuntime) stopCandidate(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	cancel := r.canaryCancel
	done := r.canaryDone
	if cancel != nil {
		cancel()
	}
	r.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.mu.Lock()
	steering := r.steering
	r.steering = nil
	pool := r.pool
	r.pool = nil
	r.mu.Unlock()
	if steering != nil {
		tables.ClearCanarySteeringRules(r.activeAtBuild, *steering)
	}
	if pool != nil {
		pool.Stop()
	}
	return nil
}

func ValidateLiveCandidateScope(active, candidate *config.Config, setID string) error {
	if active == nil || candidate == nil {
		return errors.New("candidate scope requires active and candidate configs")
	}
	if candidate.GetSetById(setID) == nil {
		return fmt.Errorf("candidate set %q does not exist", setID)
	}
	a := active.Clone()
	c := candidate.Clone()
	activeSet := a.GetSetById(setID)
	for i, set := range c.Sets {
		if set != nil && set.Id == setID {
			if activeSet == nil {
				return fmt.Errorf("active set %q does not exist", setID)
			}
			replacement := *activeSet
			c.Sets[i] = &replacement
			break
		}
	}
	c.System.Classifier = a.System.Classifier
	c.RuntimeGeneration = a.RuntimeGeneration
	c.ConfigPath = a.ConfigPath
	if !reflect.DeepEqual(a, c) {
		return errors.New("candidate changes outside the requested set or classifier control plane")
	}
	return nil
}
