package ppe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type ReconcileReason string

const (
	ReconcileStartup  ReconcileReason = "startup"
	ReconcileNDMEvent ReconcileReason = "ndm-netfilter-event"
	ReconcilePeriodic ReconcileReason = "periodic-assert"
	ReconcileManual   ReconcileReason = "manual"
)

var ErrReapplySuppressed = errors.New("PPE reapply suppressed by storm guard")

type LifecycleManager interface {
	Current() (DesiredState, bool)
	Assert(context.Context) error
	Reapply(context.Context) (TransactionResult, error)
}

type ReconcilerConfig struct {
	AssertInterval     time.Duration
	Debounce           time.Duration
	MinReapplyInterval time.Duration
	FailureBackoff     time.Duration
	OperationTimeout   time.Duration
}

func DefaultReconcilerConfig(interval time.Duration) ReconcilerConfig {
	if interval <= 0 {
		interval = 55 * time.Second
	}
	return ReconcilerConfig{
		AssertInterval:     interval,
		Debounce:           250 * time.Millisecond,
		MinReapplyInterval: 5 * time.Second,
		FailureBackoff:     15 * time.Second,
		OperationTimeout:   10 * time.Second,
	}
}

type ReconcilerStatus struct {
	Running          bool            `json:"running"`
	ActiveGeneration string          `json:"active_generation,omitempty"`
	RulesPresent     bool            `json:"rules_present"`
	LastReason       ReconcileReason `json:"last_reason,omitempty"`
	LastCheckAt      time.Time       `json:"last_check_at,omitempty"`
	LastEventAt      time.Time       `json:"last_event_at,omitempty"`
	LastReapplyAt    time.Time       `json:"last_reapply_at,omitempty"`
	LastError        string          `json:"last_error,omitempty"`
	Checks           uint64          `json:"checks"`
	Missing          uint64          `json:"missing"`
	Reapplied        uint64          `json:"reapplied"`
	Failures         uint64          `json:"failures"`
	Suppressed       uint64          `json:"suppressed"`
	CoalescedEvents  uint64          `json:"coalesced_events"`
}

type Reconciler struct {
	manager LifecycleManager
	cfg     ReconcilerConfig

	mu                sync.Mutex
	status            ReconcilerStatus
	lastAttempt       time.Time
	lastFailedAttempt time.Time
	now               func() time.Time

	events chan ReconcileReason
	stop   chan struct{}
	done   chan struct{}
	start  sync.Once
	close  sync.Once
}

func NewReconciler(manager LifecycleManager, cfg ReconcilerConfig) *Reconciler {
	defaults := DefaultReconcilerConfig(cfg.AssertInterval)
	if cfg.Debounce <= 0 {
		cfg.Debounce = defaults.Debounce
	}
	if cfg.MinReapplyInterval <= 0 {
		cfg.MinReapplyInterval = defaults.MinReapplyInterval
	}
	if cfg.FailureBackoff <= 0 {
		cfg.FailureBackoff = defaults.FailureBackoff
	}
	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = defaults.OperationTimeout
	}
	if cfg.AssertInterval <= 0 {
		cfg.AssertInterval = defaults.AssertInterval
	}
	return &Reconciler{
		manager: manager,
		cfg:     cfg,
		now:     time.Now,
		events:  make(chan ReconcileReason, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (r *Reconciler) Start(ctx context.Context) {
	if r == nil || r.manager == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.start.Do(func() {
		r.mu.Lock()
		r.status.Running = true
		r.mu.Unlock()
		go r.loop(ctx)
		r.Notify(ReconcileStartup)
	})
}

func (r *Reconciler) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	started := r.status.Running
	r.mu.Unlock()
	if !started {
		return
	}
	r.close.Do(func() { close(r.stop) })
	select {
	case <-r.done:
	case <-time.After(r.cfg.OperationTimeout):
	}
}

func (r *Reconciler) Notify(reason ReconcileReason) {
	if r == nil {
		return
	}
	now := r.now().UTC()
	r.mu.Lock()
	r.status.LastEventAt = now
	r.mu.Unlock()
	select {
	case r.events <- reason:
	default:
		r.mu.Lock()
		r.status.CoalescedEvents++
		r.mu.Unlock()
	}
}

func (r *Reconciler) Status() ReconcilerStatus {
	if r == nil {
		return ReconcilerStatus{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *Reconciler) ReconcileNow(ctx context.Context, reason ReconcileReason) error {
	if r == nil || r.manager == nil {
		return ErrNoActiveGeneration
	}
	now := r.now().UTC()
	desired, ok := r.manager.Current()
	r.mu.Lock()
	r.status.Checks++
	r.status.LastCheckAt = now
	r.status.LastReason = reason
	if ok {
		r.status.ActiveGeneration = desired.Generation
	}
	r.mu.Unlock()
	if !ok {
		r.setPresent(false, ErrNoActiveGeneration)
		return ErrNoActiveGeneration
	}
	if err := r.manager.Assert(ctx); err == nil {
		r.setPresent(true, nil)
		return nil
	} else {
		r.mu.Lock()
		r.status.Missing++
		r.status.RulesPresent = false
		r.status.LastError = err.Error()
		r.mu.Unlock()
	}

	if r.shouldSuppress(now) {
		r.mu.Lock()
		r.status.Suppressed++
		r.mu.Unlock()
		return ErrReapplySuppressed
	}
	r.mu.Lock()
	r.lastAttempt = now
	r.mu.Unlock()

	opCtx := ctx
	if opCtx == nil {
		opCtx = context.Background()
	}
	if r.cfg.OperationTimeout > 0 {
		var cancel context.CancelFunc
		opCtx, cancel = context.WithTimeout(opCtx, r.cfg.OperationTimeout)
		defer cancel()
	}
	if _, err := r.manager.Reapply(opCtx); err != nil {
		r.mu.Lock()
		r.lastFailedAttempt = now
		r.status.Failures++
		r.status.LastError = err.Error()
		r.mu.Unlock()
		return fmt.Errorf("reapply active PPE generation: %w", err)
	}
	if err := r.manager.Assert(opCtx); err != nil {
		r.mu.Lock()
		r.lastFailedAttempt = now
		r.status.Failures++
		r.status.LastError = err.Error()
		r.mu.Unlock()
		return fmt.Errorf("verify reasserted PPE generation: %w", err)
	}
	r.mu.Lock()
	r.status.Reapplied++
	r.status.RulesPresent = true
	r.status.LastReapplyAt = now
	r.status.LastError = ""
	r.lastFailedAttempt = time.Time{}
	r.mu.Unlock()
	return nil
}

func (r *Reconciler) shouldSuppress(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.lastFailedAttempt.IsZero() && now.Sub(r.lastFailedAttempt) < r.cfg.FailureBackoff {
		return true
	}
	return !r.lastAttempt.IsZero() && now.Sub(r.lastAttempt) < r.cfg.MinReapplyInterval
}

func (r *Reconciler) setPresent(present bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.RulesPresent = present
	if err == nil {
		r.status.LastError = ""
	} else {
		r.status.LastError = err.Error()
	}
}

func (r *Reconciler) loop(ctx context.Context) {
	defer close(r.done)
	defer func() {
		r.mu.Lock()
		r.status.Running = false
		r.mu.Unlock()
	}()
	ticker := time.NewTicker(r.cfg.AssertInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case reason := <-r.events:
			timer := time.NewTimer(r.cfg.Debounce)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-r.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
			draining := true
			for draining {
				select {
				case newer := <-r.events:
					reason = newer
				default:
					draining = false
				}
			}
			_ = r.ReconcileNow(ctx, reason)
		case <-ticker.C:
			_ = r.ReconcileNow(ctx, ReconcilePeriodic)
		}
	}
}
