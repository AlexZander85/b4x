package runtimecontrol

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
)

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
	// HardGateCheck runs the canonical hard-gate registry evaluation (FB-03)
	// as the final promotion gate, after canary and before BeforePromote.
	// Any non-PASS verdict blocks the transaction (StagePromote).
	HardGateCheck func(GenerationMeta) error
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
	hardGateCheck func(GenerationMeta) error
	history       []HistoryEntry
	pending       *pendingState
}

type runtimeState struct {
	meta    GenerationMeta
	runtime Runtime
}

type pendingState struct {
	meta           GenerationMeta
	runtime        Runtime
	request        ApplyRequest
	readiness      RuntimeReadiness
	canary         CanaryOutcome
	canaryComplete bool
	canaryRunning  bool
	canaryDone     chan struct{}
	preparedAt     time.Time
}

func NewManager(builder Builder, opts Options) (*Manager, error) {
	if builder == nil {
		return nil, errors.New("runtime builder is nil")
	}
	builder = WrapBuilderWithDefaultVisibility(builder)
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
	manager := &Manager{builder: builder, store: store, cooldown: NewCooldown(opts.Cooldown, clk, historyMax*4), clk: clk, enabled: opts.Enabled, b4Version: limitString(opts.B4Version, 128), historyMax: historyMax, beforePromote: opts.BeforePromote, hardGateCheck: opts.HardGateCheck}
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
	syncInitialVisibilityRequirement(cfg, meta.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	record := recordFrom(meta, CanaryOutcome{Passed: true, Samples: 1, StartedAt: meta.CreatedAt, CompletedAt: meta.CreatedAt}, m.b4Version, meta.CreatedAt)
	if err := m.store.Prepare(record); err != nil {
		return &TransactionError{Stage: StagePrepare, Err: err}
	}
	if err := m.store.Commit(record); err != nil {
		_ = m.store.Abort()
		return &TransactionError{Stage: StageCommit, Err: err}
	}
	m.active.Store(&runtimeState{meta: meta, runtime: runtime})
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

func (m *Manager) Pending() (*PendingGeneration, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return nil, false
	}
	out := pendingSnapshot(m.pending)
	return &out, true
}

func (m *Manager) Status() ManagerStatus {
	if m == nil {
		return ManagerStatus{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	status := ManagerStatus{Enabled: m.enabled}
	if active := m.active.Load(); active != nil {
		meta := active.meta.clone()
		status.Active = &meta
	}
	if m.pending != nil {
		pending := pendingSnapshot(m.pending)
		status.Pending = &pending
	}
	if m.lastGood != nil {
		last := m.lastGood.clone()
		status.LastGood = &last
	}
	status.History = make([]HistoryEntry, len(m.history))
	copy(status.History, m.history)
	return status
}

func pendingSnapshot(p *pendingState) PendingGeneration {
	return PendingGeneration{
		Generation: p.meta.clone(), Readiness: p.readiness, CanarySpec: p.request.Canary,
		Canary: cloneCanary(p.canary), CanaryComplete: p.canaryComplete, CanaryRunning: p.canaryRunning, PreparedAt: p.preparedAt,
	}
}

// Prepare validates and allocates a candidate runtime without changing the
// active production generation.
