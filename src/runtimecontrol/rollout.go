// Package runtimecontrol owns the control-plane transaction for a B4 runtime
// generation. It deliberately does not inspect packets or hold flow state.
// Packet-path implementations are supplied through Runtime, which keeps the
// control plane testable and prevents a hot apply from retaining mutable
// config pointers in long-lived flow state.
package runtimecontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

const (
	LastGoodSchemaVersion = 1
	DefaultHistoryLimit   = 64
	DefaultCooldown       = 30 * time.Second
	MaxCanaryDuration     = time.Hour
	MaxCanarySamples      = 1000000
)

var (
	ErrDisabled       = errors.New("transactional runtime apply is disabled")
	ErrNoActive       = errors.New("no active runtime generation")
	ErrNoRollback     = errors.New("no previous last-good generation is available for rollback")
	ErrCooldown       = errors.New("candidate is in cooldown")
	ErrInvalidCanary  = errors.New("invalid canary specification")
	ErrInvalidRuntime = errors.New("runtime implementation is nil")
)

type Stage string

const (
	StageValidate  Stage = "validate"
	StageBuild     Stage = "build"
	StageReadiness Stage = "readiness"
	StageCanary    Stage = "canary"
	StagePrepare   Stage = "last-good-prepare"
	StagePromote   Stage = "promote"
	StageCommit    Stage = "last-good-commit"
	StageDrain     Stage = "drain"
	StageRollback  Stage = "rollback"
)

// TransactionError preserves the failure stage for API/trace consumers.
type TransactionError struct {
	Stage Stage
	Err   error
}

func (e *TransactionError) Error() string {
	if e == nil {
		return "runtime transaction failed"
	}
	return fmt.Sprintf("runtime transaction %s: %v", e.Stage, e.Err)
}

func (e *TransactionError) Unwrap() error { return e.Err }

type ValidationSummary struct {
	Valid        bool      `json:"valid"`
	Errors       []string  `json:"errors,omitempty"`
	CheckedAt    time.Time `json:"checked_at"`
	ConfigSchema int       `json:"config_schema"`
}

type GenerationMeta struct {
	ID            string            `json:"id"`
	ConfigHash    string            `json:"config_hash"`
	SchemaVersion int               `json:"schema_version"`
	StrategyIDs   []string          `json:"strategy_ids,omitempty"`
	SetIDs        []string          `json:"set_ids,omitempty"`
	Validation    ValidationSummary `json:"validation"`
	CreatedAt     time.Time         `json:"created_at"`
}

func (m GenerationMeta) clone() GenerationMeta {
	m.StrategyIDs = append([]string(nil), m.StrategyIDs...)
	m.SetIDs = append([]string(nil), m.SetIDs...)
	m.Validation.Errors = append([]string(nil), m.Validation.Errors...)
	return m
}

type RuntimeReadiness struct {
	Ready      bool      `json:"ready"`
	CheckedAt  time.Time `json:"checked_at"`
	Reason     string    `json:"reason,omitempty"`
	QueueDrops uint64    `json:"queue_drops,omitempty"`
	UserDrops  uint64    `json:"user_drops,omitempty"`
}

// Runtime is an allocated but not-yet-promoted immutable generation. The
// implementation owns queue workers, held-flow cleanup and action-token
// invalidation. Every method must be bounded and idempotent where noted.
type Runtime interface {
	Readiness(context.Context) (RuntimeReadiness, error)
	Canary(context.Context, CanarySpec) (CanaryOutcome, error)
	Promote(context.Context) error
	Drain(context.Context) error
	Resume(context.Context) error
	Rollback(context.Context, string) error
	Close(context.Context) error
}

type Builder interface {
	Build(context.Context, *config.Config, GenerationMeta) (Runtime, error)
}

type BuilderFunc func(context.Context, *config.Config, GenerationMeta) (Runtime, error)

func (f BuilderFunc) Build(ctx context.Context, cfg *config.Config, meta GenerationMeta) (Runtime, error) {
	if f == nil {
		return nil, ErrInvalidRuntime
	}
	return f(ctx, cfg, meta)
}

type CanaryStopConditions struct {
	MaxFailures             uint64  `json:"max_failures,omitempty"`
	MaxFailureRate          float64 `json:"max_failure_rate,omitempty"`
	StopOnQueueDrops        bool    `json:"stop_on_queue_drops,omitempty"`
	StopOnCaptureIncomplete bool    `json:"stop_on_capture_incomplete,omitempty"`
}

type CanarySpec struct {
	ClientGroup    string               `json:"client_group"`
	SetID          string               `json:"set_id"`
	Protocol       string               `json:"protocol"`
	NewFlowPercent uint8                `json:"new_flow_percent"`
	Duration       time.Duration        `json:"duration"`
	MinSamples     uint64               `json:"min_samples"`
	Stop           CanaryStopConditions `json:"stop_conditions"`
}

func (s CanarySpec) Validate() error {
	if strings.TrimSpace(s.ClientGroup) == "" || strings.TrimSpace(s.SetID) == "" {
		return fmt.Errorf("%w: client_group and set_id are required", ErrInvalidCanary)
	}
	if s.NewFlowPercent == 0 || s.NewFlowPercent > 100 {
		return fmt.Errorf("%w: new_flow_percent must be 1..100", ErrInvalidCanary)
	}
	if s.Duration <= 0 || s.Duration > MaxCanaryDuration {
		return fmt.Errorf("%w: duration must be greater than zero and at most %s", ErrInvalidCanary, MaxCanaryDuration)
	}
	if s.MinSamples == 0 || s.MinSamples > MaxCanarySamples {
		return fmt.Errorf("%w: min_samples must be 1..%d", ErrInvalidCanary, MaxCanarySamples)
	}
	if s.Stop.MaxFailures == 0 && s.Stop.MaxFailureRate <= 0 && !s.Stop.StopOnQueueDrops && !s.Stop.StopOnCaptureIncomplete {
		return fmt.Errorf("%w: at least one explicit stop condition is required", ErrInvalidCanary)
	}
	if s.Stop.MaxFailureRate < 0 || s.Stop.MaxFailureRate > 1 {
		return fmt.Errorf("%w: max_failure_rate must be between 0 and 1", ErrInvalidCanary)
	}
	return nil
}

type CanaryOutcome struct {
	Passed            bool      `json:"passed"`
	Samples           uint64    `json:"samples"`
	Failures          uint64    `json:"failures"`
	FailureRate       float64   `json:"failure_rate"`
	QueueDrops        uint64    `json:"queue_drops,omitempty"`
	CaptureIncomplete bool      `json:"capture_incomplete,omitempty"`
	StopReason        string    `json:"stop_reason,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	CompletedAt       time.Time `json:"completed_at"`
}

type ApplyRequest struct {
	Canary CanarySpec
}

type ApplyResult struct {
	Generation GenerationMeta   `json:"generation"`
	Readiness  RuntimeReadiness `json:"readiness"`
	Canary     CanaryOutcome    `json:"canary"`
	DrainError string           `json:"drain_error,omitempty"`
}

type RollbackResult struct {
	Generation GenerationMeta `json:"generation"`
	Reason     string         `json:"reason"`
}

type LastGoodRecord struct {
	SchemaVersion  int               `json:"schema_version"`
	ConfigHash     string            `json:"config_hash"`
	GenerationHash string            `json:"generation_hash"`
	StrategyIDs    []string          `json:"strategy_ids,omitempty"`
	SetIDs         []string          `json:"set_ids,omitempty"`
	Validation     ValidationSummary `json:"validation"`
	B4Version      string            `json:"b4_version"`
	Timestamp      time.Time         `json:"timestamp"`
	Canary         CanaryOutcome     `json:"canary_outcome"`
}

func recordFrom(meta GenerationMeta, outcome CanaryOutcome, version string, now time.Time) LastGoodRecord {
	return LastGoodRecord{
		SchemaVersion: LastGoodSchemaVersion, ConfigHash: meta.ConfigHash, GenerationHash: meta.ID,
		StrategyIDs: append([]string(nil), meta.StrategyIDs...), SetIDs: append([]string(nil), meta.SetIDs...),
		Validation: meta.Validation, B4Version: limitString(version, 128), Timestamp: now, Canary: outcome,
	}
}

func (r LastGoodRecord) clone() LastGoodRecord {
	r.StrategyIDs = append([]string(nil), r.StrategyIDs...)
	r.SetIDs = append([]string(nil), r.SetIDs...)
	r.Validation.Errors = append([]string(nil), r.Validation.Errors...)
	return r
}

// LastGoodStore persists metadata only. It must never persist live flows,
// hints, raw packets or mutable runtime pointers.
type LastGoodStore interface {
	Prepare(LastGoodRecord) error
	Commit(LastGoodRecord) error
	Abort() error
	Load() (*LastGoodRecord, error)
}

type MemoryLastGoodStore struct {
	mu      sync.Mutex
	pending *LastGoodRecord
	good    *LastGoodRecord
}

func (s *MemoryLastGoodStore) Prepare(record LastGoodRecord) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := record.clone()
	s.pending = &r
	return nil
}
func (s *MemoryLastGoodStore) Commit(record LastGoodRecord) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := record.clone()
	s.good = &r
	s.pending = nil
	return nil
}
func (s *MemoryLastGoodStore) Abort() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = nil
	return nil
}
func (s *MemoryLastGoodStore) Load() (*LastGoodRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.good == nil {
		return nil, nil
	}
	r := s.good.clone()
	return &r, nil
}

type diskLastGood struct {
	SchemaVersion int            `json:"schema_version"`
	State         string         `json:"state"`
	Record        LastGoodRecord `json:"record"`
}

// FileLastGoodStore uses a pending sidecar followed by an atomic committed
// file. A crash before Commit leaves the previous committed record intact.
type FileLastGoodStore struct {
	Path string
	mu   sync.Mutex
}

func (s *FileLastGoodStore) Prepare(record LastGoodRecord) error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return errors.New("last-good path is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeAtomic(s.Path+".pending", diskLastGood{SchemaVersion: LastGoodSchemaVersion, State: "pending", Record: record.clone()})
}
func (s *FileLastGoodStore) Commit(record LastGoodRecord) error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return errors.New("last-good path is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeAtomic(s.Path, diskLastGood{SchemaVersion: LastGoodSchemaVersion, State: "committed", Record: record.clone()}); err != nil {
		return err
	}
	_ = os.Remove(s.Path + ".pending")
	return nil
}
func (s *FileLastGoodStore) Abort() error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.Path + ".pending"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (s *FileLastGoodStore) Load() (*LastGoodRecord, error) {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return nil, errors.New("last-good path is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var disk diskLastGood
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, fmt.Errorf("decode last-good: %w", err)
	}
	if disk.SchemaVersion != LastGoodSchemaVersion || disk.State != "committed" || disk.Record.SchemaVersion != LastGoodSchemaVersion {
		return nil, fmt.Errorf("unsupported last-good record")
	}
	r := disk.Record.clone()
	return &r, nil
}
func (s *FileLastGoodStore) writeAtomic(path string, value diskLastGood) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".b4-last-good-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	encErr := json.NewEncoder(tmp).Encode(value)
	if encErr == nil {
		encErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if encErr != nil {
		cleanup()
		return encErr
	}
	if closeErr != nil {
		cleanup()
		return closeErr
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

type CooldownKey struct {
	SetID               string `json:"set_id"`
	ClientGroup         string `json:"client_group"`
	Protocol            string `json:"protocol"`
	CandidateGeneration string `json:"candidate_generation"`
}

type Cooldown struct {
	mu       sync.Mutex
	clock    clock.Clock
	duration time.Duration
	max      int
	entries  map[CooldownKey]time.Time
}

func NewCooldown(duration time.Duration, clk clock.Clock, maxEntries int) *Cooldown {
	if duration <= 0 {
		duration = DefaultCooldown
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	if maxEntries <= 0 {
		maxEntries = 256
	}
	return &Cooldown{clock: clk, duration: duration, max: maxEntries, entries: make(map[CooldownKey]time.Time)}
}

func (c *Cooldown) Check(key CooldownKey) error {
	if c == nil {
		return nil
	}
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for candidate, until := range c.entries {
		if !now.Before(until) {
			delete(c.entries, candidate)
		}
	}
	if until, ok := c.entries[key]; ok && now.Before(until) {
		return fmt.Errorf("%w until %s", ErrCooldown, until.UTC().Format(time.RFC3339Nano))
	}
	return nil
}
func (c *Cooldown) RecordFailure(key CooldownKey) {
	if c == nil {
		return
	}
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		var oldest CooldownKey
		var oldestAt time.Time
		for candidate, at := range c.entries {
			if oldestAt.IsZero() || at.Before(oldestAt) {
				oldest, oldestAt = candidate, at
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[key] = now.Add(c.duration)
}
func (c *Cooldown) RecordSuccess(key CooldownKey) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}
func (c *Cooldown) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

type HistoryEntry struct {
	Action     string        `json:"action"`
	Generation string        `json:"generation"`
	Reason     string        `json:"reason,omitempty"`
	Success    bool          `json:"success"`
	At         time.Time     `json:"at"`
	Canary     CanaryOutcome `json:"canary,omitempty"`
}

type Options struct {
	Enabled       bool
	B4Version     string
	Clock         clock.Clock
	LastGood      LastGoodStore
	Cooldown      time.Duration
	HistoryLimit  int
	BeforePromote func(GenerationMeta) error // deterministic fault injection/diagnostics hook
}

type Manager struct {
	mu            sync.Mutex
	active        atomic.Pointer[runtimeState]
	retired       *runtimeState
	previousGood  *LastGoodRecord
	lastGood      *LastGoodRecord
	builder       Builder
	store         LastGoodStore
	cooldown      *Cooldown
	clk           clock.Clock
	enabled       bool
	b4Version     string
	historyMax    int
	beforePromote func(GenerationMeta) error
	history       []HistoryEntry
}

type runtimeState struct {
	meta    GenerationMeta
	runtime Runtime
}

func NewManager(builder Builder, opts Options) (*Manager, error) {
	if builder == nil {
		return nil, errors.New("runtime builder is nil")
	}
	clk := opts.Clock
	if clk == nil {
		clk = clock.RealClock{}
	}
	store := opts.LastGood
	if store == nil {
		store = &MemoryLastGoodStore{}
	}
	historyMax := opts.HistoryLimit
	if historyMax <= 0 {
		historyMax = DefaultHistoryLimit
	}
	manager := &Manager{builder: builder, store: store, cooldown: NewCooldown(opts.Cooldown, clk, historyMax*4), clk: clk, enabled: opts.Enabled, b4Version: limitString(opts.B4Version, 128), historyMax: historyMax, beforePromote: opts.BeforePromote}
	lastGood, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("load last-good: %w", err)
	}
	manager.lastGood = lastGood
	return manager, nil
}

func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}
func (m *Manager) SetEnabled(enabled bool) {
	if m != nil {
		m.mu.Lock()
		m.enabled = enabled
		m.mu.Unlock()
	}
}

func (m *Manager) InstallInitial(cfg *config.Config, runtime Runtime) error {
	if m == nil || cfg == nil || runtime == nil {
		return ErrInvalidRuntime
	}
	if err := cfg.Validate(); err != nil {
		return &TransactionError{Stage: StageValidate, Err: err}
	}
	meta := makeGenerationMeta(cfg, m.clk.Now())
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active.Store(&runtimeState{meta: meta, runtime: runtime})
	record := recordFrom(meta, CanaryOutcome{Passed: true, Samples: 1, StartedAt: meta.CreatedAt, CompletedAt: meta.CreatedAt}, m.b4Version, meta.CreatedAt)
	m.lastGood = &record
	return nil
}

func (m *Manager) Active() (GenerationMeta, bool) {
	if m == nil {
		return GenerationMeta{}, false
	}
	state := m.active.Load()
	if state == nil {
		return GenerationMeta{}, false
	}
	return state.meta.clone(), true
}

func (m *Manager) LastGood() (*LastGoodRecord, error) {
	if m == nil {
		return nil, ErrNoActive
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastGood != nil {
		r := m.lastGood.clone()
		return &r, nil
	}
	return m.store.Load()
}

func (m *Manager) History() []HistoryEntry {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HistoryEntry, len(m.history))
	copy(out, m.history)
	for i := range out {
		out[i].Canary = cloneCanary(out[i].Canary)
	}
	return out
}

func (m *Manager) Apply(ctx context.Context, candidate *config.Config, request ApplyRequest) (ApplyResult, error) {
	if m == nil {
		return ApplyResult{}, ErrInvalidRuntime
	}
	if !m.Enabled() {
		return ApplyResult{}, ErrDisabled
	}
	if candidate == nil {
		return ApplyResult{}, &TransactionError{Stage: StageValidate, Err: errors.New("candidate config is nil")}
	}
	if err := request.Canary.Validate(); err != nil {
		return ApplyResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	clone := candidate.CloneForRuntimeUpdate()
	if err := clone.Validate(); err != nil {
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Reason: err.Error(), Success: false, At: m.clk.Now()})
		return ApplyResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	meta := makeGenerationMeta(clone, m.clk.Now())
	key := CooldownKey{SetID: request.Canary.SetID, ClientGroup: request.Canary.ClientGroup, Protocol: request.Canary.Protocol, CandidateGeneration: meta.ID}
	if err := m.cooldown.Check(key); err != nil {
		return ApplyResult{}, &TransactionError{Stage: StageCanary, Err: err}
	}

	runtime, err := m.builder.Build(ctx, clone, meta.clone())
	if err != nil || runtime == nil {
		if err == nil {
			err = ErrInvalidRuntime
		}
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now()})
		return ApplyResult{}, &TransactionError{Stage: StageBuild, Err: err}
	}
	readiness, err := runtime.Readiness(ctx)
	if err != nil || !readiness.Ready {
		if err == nil {
			err = errors.New(readiness.Reason)
		}
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now()})
		return ApplyResult{Generation: meta, Readiness: readiness}, &TransactionError{Stage: StageReadiness, Err: err}
	}
	canary, err := runtime.Canary(ctx, request.Canary)
	if err == nil {
		err = validateCanaryOutcome(request.Canary, canary)
	}
	if err != nil {
		m.cooldown.RecordFailure(key)
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
		return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StageCanary, Err: err}
	}
	record := recordFrom(meta, canary, m.b4Version, m.clk.Now())
	if err := m.store.Prepare(record); err != nil {
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StagePrepare, Err: err}
	}
	old := m.active.Load()
	if m.beforePromote != nil {
		if err := m.beforePromote(meta.clone()); err != nil {
			_ = m.store.Abort()
			m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
			m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
			return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StagePromote, Err: err}
		}
	}
	if err := runtime.Promote(ctx); err != nil {
		_ = m.store.Abort()
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
		return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StagePromote, Err: err}
	}
	candidateState := &runtimeState{meta: meta, runtime: runtime}
	m.active.Store(candidateState)
	if err := m.store.Commit(record); err != nil {
		m.active.Store(old)
		_ = m.store.Abort()
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
		return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StageCommit, Err: err}
	}
	result := ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}
	if old != nil {
		if err := old.runtime.Drain(ctx); err != nil {
			result.DrainError = err.Error()
		}
		if m.retired != nil {
			_ = m.retired.runtime.Close(ctx)
		}
		m.retired = old
		if m.lastGood != nil {
			previous := m.lastGood.clone()
			m.previousGood = &previous
		}
	}
	m.lastGood = &record
	m.cooldown.RecordSuccess(key)
	if result.DrainError != "" {
		observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidateRollback, map[string]string{"reason": "drain-error"}, 1)
	}
	m.appendHistoryLocked(HistoryEntry{Action: "promote", Generation: meta.ID, Success: true, At: m.clk.Now(), Canary: canary})
	observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidatePromote, map[string]string{"generation": meta.ID[:minInt(len(meta.ID), 16)]}, 1)
	return result, nil
}

func (m *Manager) Rollback(ctx context.Context, reason string) (RollbackResult, error) {
	if m == nil {
		return RollbackResult{}, ErrInvalidRuntime
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.active.Load()
	if current == nil {
		return RollbackResult{}, ErrNoActive
	}
	if m.retired == nil {
		return RollbackResult{}, ErrNoRollback
	}
	if err := ctx.Err(); err != nil {
		return RollbackResult{}, &TransactionError{Stage: StageRollback, Err: err}
	}
	previous := m.retired
	previousRecord := m.recordForStateLocked(previous)
	if err := m.store.Prepare(previousRecord); err != nil {
		return RollbackResult{}, &TransactionError{Stage: StagePrepare, Err: err}
	}
	if err := previous.runtime.Resume(ctx); err != nil {
		_ = m.store.Abort()
		return RollbackResult{}, &TransactionError{Stage: StageRollback, Err: err}
	}
	m.active.Store(previous)
	if err := m.store.Commit(previousRecord); err != nil {
		m.active.Store(current)
		_ = previous.runtime.Drain(ctx)
		_ = m.store.Abort()
		return RollbackResult{}, &TransactionError{Stage: StageCommit, Err: err}
	}
	if err := current.runtime.Rollback(ctx, reason); err != nil {
		return RollbackResult{}, &TransactionError{Stage: StageRollback, Err: err}
	}
	_ = current.runtime.Close(ctx)
	m.retired = nil
	if m.previousGood != nil {
		m.lastGood = m.previousGood
		m.previousGood = nil
	} else {
		m.lastGood = nil
	}
	m.appendHistoryLocked(HistoryEntry{Action: "rollback", Generation: previous.meta.ID, Reason: limitString(reason, 256), Success: true, At: m.clk.Now()})
	observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidateRollback, map[string]string{"reason": sanitizeLabel(reason)}, 1)
	return RollbackResult{Generation: previous.meta.clone(), Reason: limitString(reason, 256)}, nil
}

func (m *Manager) recordForStateLocked(state *runtimeState) LastGoodRecord {
	if state == nil {
		return LastGoodRecord{SchemaVersion: LastGoodSchemaVersion, B4Version: m.b4Version, Timestamp: m.clk.Now()}
	}
	if m.previousGood != nil && m.retired == state {
		r := m.previousGood.clone()
		r.Timestamp = m.clk.Now()
		return r
	}
	return recordFrom(state.meta, CanaryOutcome{Passed: true, Samples: 1, StartedAt: state.meta.CreatedAt, CompletedAt: m.clk.Now()}, m.b4Version, m.clk.Now())
}

func (m *Manager) cleanupCandidateLocked(ctx context.Context, runtime Runtime, generation string, cause error) {
	_ = runtime.Rollback(ctx, cause.Error())
	_ = runtime.Close(ctx)
	observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidateRollback, map[string]string{"reason": sanitizeLabel(cause.Error())}, 1)
}

func (m *Manager) appendHistoryLocked(entry HistoryEntry) {
	entry.Generation = limitString(entry.Generation, 128)
	entry.Reason = limitString(entry.Reason, 256)
	m.history = append(m.history, entry)
	if len(m.history) > m.historyMax {
		m.history = append([]HistoryEntry(nil), m.history[len(m.history)-m.historyMax:]...)
	}
}

func validateCanaryOutcome(spec CanarySpec, outcome CanaryOutcome) error {
	if outcome.Samples < spec.MinSamples {
		return fmt.Errorf("canary minimum samples not met: got %d, need %d", outcome.Samples, spec.MinSamples)
	}
	rate := outcome.FailureRate
	if rate == 0 && outcome.Samples > 0 {
		rate = float64(outcome.Failures) / float64(outcome.Samples)
	}
	if spec.Stop.MaxFailures > 0 && outcome.Failures > spec.Stop.MaxFailures {
		return fmt.Errorf("canary stop condition: failures=%d exceeds %d", outcome.Failures, spec.Stop.MaxFailures)
	}
	if spec.Stop.MaxFailureRate > 0 && rate > spec.Stop.MaxFailureRate {
		return fmt.Errorf("canary stop condition: failure_rate=%.4f exceeds %.4f", rate, spec.Stop.MaxFailureRate)
	}
	if spec.Stop.StopOnQueueDrops && outcome.QueueDrops > 0 {
		return fmt.Errorf("canary stop condition: queue drops=%d", outcome.QueueDrops)
	}
	if spec.Stop.StopOnCaptureIncomplete && outcome.CaptureIncomplete {
		return errors.New("canary stop condition: capture incomplete")
	}
	if !outcome.StartedAt.IsZero() && !outcome.CompletedAt.IsZero() {
		if outcome.CompletedAt.Before(outcome.StartedAt) {
			return errors.New("canary timestamps are out of order")
		}
		if outcome.CompletedAt.Sub(outcome.StartedAt) > spec.Duration {
			return fmt.Errorf("canary duration exceeded: %s", outcome.CompletedAt.Sub(outcome.StartedAt))
		}
	}
	if !outcome.Passed {
		if outcome.StopReason != "" {
			return errors.New(outcome.StopReason)
		}
		return errors.New("canary reported failure")
	}
	return nil
}

func makeGenerationMeta(cfg *config.Config, now time.Time) GenerationMeta {
	hash := fingerprintConfig(cfg)
	setIDs := make([]string, 0, len(cfg.Sets))
	strategyIDs := make([]string, 0, len(cfg.Sets))
	for i, set := range cfg.Sets {
		if set == nil {
			continue
		}
		id := strings.TrimSpace(set.Id)
		if id == "" {
			id = fmt.Sprintf("set-%d", i)
		}
		setIDs = append(setIDs, id)
		strategyIDs = append(strategyIDs, id+":tcp="+set.TCP.Desync.Mode+":udp="+set.UDP.FakingStrategy+":frag="+set.Fragmentation.Strategy)
	}
	sort.Strings(setIDs)
	sort.Strings(strategyIDs)
	return GenerationMeta{ID: hash, ConfigHash: hash, SchemaVersion: cfg.System.Classifier.SchemaVersion, StrategyIDs: setIDsToStrategies(strategyIDs), SetIDs: setIDs, Validation: ValidationSummary{Valid: true, CheckedAt: now, ConfigSchema: cfg.System.Classifier.SchemaVersion}, CreatedAt: now}
}

func setIDsToStrategies(ids []string) []string { return append([]string(nil), ids...) }

func fingerprintConfig(cfg *config.Config) string {
	clone := cfg.Clone()
	clone.ConfigPath = ""
	clone.RuntimeGeneration = ""
	clone.System.WebServer.Password = ""
	clone.System.API.IPInfoToken = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sanitizeLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return limitString(b.String(), 64)
}
func limitString(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func cloneCanary(c CanaryOutcome) CanaryOutcome { return c }
