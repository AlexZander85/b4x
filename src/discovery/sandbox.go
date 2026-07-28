package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

const (
	SandboxBaselineNone       SandboxMode = "baseline-none"
	SandboxBaselineProduction SandboxMode = "baseline-production"
	SandboxCandidate          SandboxMode = "candidate"

	SandboxPending       SandboxState = "pending"
	SandboxReady         SandboxState = "ready"
	SandboxClosing       SandboxState = "closing"
	SandboxCleanupFailed SandboxState = "cleanup-failed"
)

var (
	ErrSandboxBackendUnavailable = errors.New("discovery sandbox backend unavailable")
	ErrSandboxQueueCollision     = errors.New("discovery sandbox queue collision")
	ErrSandboxPortCollision      = errors.New("discovery sandbox source-port collision")
	ErrSandboxMarkCollision      = errors.New("discovery sandbox mark collision")
	ErrSandboxLeaseCollision     = errors.New("discovery sandbox lease already exists")
	ErrSandboxNotReady           = errors.New("discovery sandbox queue owner is not ready")
	ErrSandboxUnknown            = errors.New("discovery sandbox is unknown")
)

type SandboxMode string
type SandboxState string

// SandboxSpec is an immutable value copied into the lease. It contains no
// config pointer so a long-lived experiment cannot observe a hot-reloaded
// production config accidentally.
type SandboxSpec struct {
	ID                string      `json:"id"`
	Mode              SandboxMode `json:"mode"`
	QueueStart        uint16      `json:"queue_start"`
	QueueThreads      uint16      `json:"queue_threads"`
	SourcePortMin     uint16      `json:"source_port_min"`
	SourcePortMax     uint16      `json:"source_port_max"`
	FlowMark          uint32      `json:"flow_mark"`
	ProcessedMark     uint32      `json:"processed_mark"`
	ConfigGeneration  string      `json:"config_generation,omitempty"`
	OwnerToken        string      `json:"owner_token"`
	ExecutorEnabled   bool        `json:"executor_enabled"`
	ExcludeProduction bool        `json:"exclude_production"`
	ExcludeCandidate  bool        `json:"exclude_candidate"`
}

func (s SandboxSpec) QueueEnd() uint32 {
	if s.QueueThreads == 0 {
		return uint32(s.QueueStart)
	}
	return uint32(s.QueueStart) + uint32(s.QueueThreads) - 1
}

func (s SandboxSpec) HasSourcePortRange() bool {
	return s.SourcePortMin != 0 || s.SourcePortMax != 0
}

func (s SandboxSpec) Validate() error {
	if strings.TrimSpace(s.ID) == "" || len(s.ID) > 96 {
		return fmt.Errorf("sandbox id must be 1..96 characters")
	}
	switch s.Mode {
	case SandboxBaselineNone, SandboxBaselineProduction, SandboxCandidate:
	default:
		return fmt.Errorf("unsupported sandbox mode %q", s.Mode)
	}
	if s.QueueThreads == 0 || s.QueueThreads > 256 || s.QueueEnd() > 65535 {
		return fmt.Errorf("sandbox queue range is invalid: %d-%d", s.QueueStart, s.QueueEnd())
	}
	if s.FlowMark == 0 || s.ProcessedMark == 0 || s.FlowMark == s.ProcessedMark {
		return fmt.Errorf("sandbox flow and processed marks must be non-zero and distinct")
	}
	if len(s.OwnerToken) == 0 || len(s.OwnerToken) > 96 {
		return fmt.Errorf("sandbox owner token must be 1..96 characters")
	}
	if s.HasSourcePortRange() {
		if s.SourcePortMin < 1024 || s.SourcePortMax < s.SourcePortMin || s.SourcePortMax == 0 {
			return fmt.Errorf("sandbox source-port range is invalid: %d-%d", s.SourcePortMin, s.SourcePortMax)
		}
	}
	switch s.Mode {
	case SandboxBaselineNone:
		if s.ExecutorEnabled || !s.ExcludeProduction || !s.ExcludeCandidate {
			return fmt.Errorf("baseline-none must exclude both executors")
		}
	case SandboxBaselineProduction:
		if s.ExecutorEnabled || s.ExcludeProduction || !s.ExcludeCandidate {
			return fmt.Errorf("baseline-production must use production only")
		}
	case SandboxCandidate:
		if !s.ExecutorEnabled || !s.ExcludeProduction || !s.HasSourcePortRange() {
			return fmt.Errorf("candidate requires isolated source ports and production exclusion")
		}
	}
	return nil
}

// ValidateSandboxIsolation is checked before touching a queue or firewall.
// The rules deliberately reject ambiguity rather than trying to merge ranges.
func ValidateSandboxIsolation(a, b SandboxSpec) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("sandbox %s: %w", a.ID, err)
	}
	if err := b.Validate(); err != nil {
		return fmt.Errorf("sandbox %s: %w", b.ID, err)
	}
	if rangesOverlap(uint32(a.QueueStart), a.QueueEnd(), uint32(b.QueueStart), b.QueueEnd()) {
		return fmt.Errorf("%w: %s and %s", ErrSandboxQueueCollision, a.ID, b.ID)
	}
	if a.FlowMark == b.FlowMark || a.ProcessedMark == b.ProcessedMark || a.FlowMark == b.ProcessedMark || a.ProcessedMark == b.FlowMark {
		return fmt.Errorf("%w: %s and %s", ErrSandboxMarkCollision, a.ID, b.ID)
	}
	if a.HasSourcePortRange() && b.HasSourcePortRange() && rangesOverlap(uint32(a.SourcePortMin), uint32(a.SourcePortMax), uint32(b.SourcePortMin), uint32(b.SourcePortMax)) {
		return fmt.Errorf("%w: %s and %s", ErrSandboxPortCollision, a.ID, b.ID)
	}
	if a.Mode == SandboxCandidate && b.Mode == SandboxBaselineProduction && !a.ExcludeProduction {
		return fmt.Errorf("candidate %s is not excluded from production", a.ID)
	}
	if b.Mode == SandboxCandidate && a.Mode == SandboxBaselineProduction && !b.ExcludeProduction {
		return fmt.Errorf("candidate %s is not excluded from production", b.ID)
	}
	return nil
}

func rangesOverlap(aStart, aEnd, bStart, bEnd uint32) bool {
	return aStart <= bEnd && bStart <= aEnd
}

// SandboxSpecFromConfig copies only the immutable values needed for steering.
// It is useful to build all three modes from the same active config snapshot.
func SandboxSpecFromConfig(cfg *config.Config, mode SandboxMode, id string, queueStart, queueThreads uint16, sourceMin, sourceMax uint16) (SandboxSpec, error) {
	if cfg == nil {
		return SandboxSpec{}, errors.New("sandbox config is nil")
	}
	spec := SandboxSpec{
		ID:               id,
		Mode:             mode,
		QueueStart:       queueStart,
		QueueThreads:     queueThreads,
		SourcePortMin:    sourceMin,
		SourcePortMax:    sourceMax,
		ConfigGeneration: cfg.RuntimeGeneration,
		OwnerToken:       "config-bound",
	}
	switch mode {
	case SandboxBaselineNone:
		spec.FlowMark = uint32(cfg.DiscoveryFlowMark())
		spec.ProcessedMark = uint32(cfg.DiscoveryInjectedMark())
		spec.ExcludeProduction = true
		spec.ExcludeCandidate = true
	case SandboxBaselineProduction:
		spec.FlowMark = uint32(cfg.MainInjectedMark())
		if uint64(spec.FlowMark)+3 > uint64(^uint32(0)) {
			return SandboxSpec{}, errors.New("sandbox production processed mark overflows uint32")
		}
		spec.ProcessedMark = spec.FlowMark + 3
		spec.ExcludeCandidate = true
	case SandboxCandidate:
		if uint64(cfg.DiscoveryFlowMark())+3 > uint64(^uint32(0)) || uint64(cfg.DiscoveryInjectedMark())+3 > uint64(^uint32(0)) {
			return SandboxSpec{}, errors.New("sandbox candidate mark overflows uint32")
		}
		spec.FlowMark = uint32(cfg.DiscoveryFlowMark()) + 3
		spec.ProcessedMark = uint32(cfg.DiscoveryInjectedMark()) + 3
		spec.ExecutorEnabled = true
		spec.ExcludeProduction = true
	default:
		return SandboxSpec{}, fmt.Errorf("unsupported sandbox mode %q", mode)
	}
	return spec, nil
}

type QueueOwnerState struct {
	QueueNumber uint16 `json:"queue_number"`
	OwnerPortID uint32 `json:"owner_port_id"`
	Expected    uint32 `json:"expected_owner_port_id,omitempty"`
	Present     bool   `json:"present"`
}

type QueueReadiness struct {
	CheckedAt     time.Time         `json:"checked_at"`
	Ready         bool              `json:"ready"`
	OwnerVerified bool              `json:"owner_verified"`
	Stale         bool              `json:"stale"`
	Queues        []QueueOwnerState `json:"queues,omitempty"`
	Reason        string            `json:"reason,omitempty"`
}

type SandboxLease struct {
	Spec      SandboxSpec  `json:"spec"`
	State     SandboxState `json:"state"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

type SandboxEvent struct {
	Timestamp time.Time   `json:"timestamp"`
	SandboxID string      `json:"sandbox_id"`
	Mode      SandboxMode `json:"mode"`
	Kind      string      `json:"kind"`
	Reason    string      `json:"reason,omitempty"`
}

type SandboxBackend interface {
	Apply(context.Context, SandboxSpec) error
	Readiness(context.Context, SandboxSpec) (QueueReadiness, error)
	Cleanup(context.Context, SandboxSpec) error
}

type SandboxLeaseStore interface {
	Load(context.Context) ([]SandboxLease, error)
	Save(context.Context, SandboxLease) error
	Delete(context.Context, string) error
}

type SandboxManagerConfig struct {
	Backend    SandboxBackend
	Leases     SandboxLeaseStore
	Clock      clock.Clock
	MaxActive  int
	MaxEvents  int
	OwnerToken string
}

func DefaultSandboxManagerConfig() SandboxManagerConfig {
	return SandboxManagerConfig{Clock: clock.RealClock{}, MaxActive: 8, MaxEvents: 256}
}

type sandboxEntry struct {
	lease SandboxLease
}

type SandboxManager struct {
	mu         sync.Mutex
	active     map[string]*sandboxEntry
	config     SandboxManagerConfig
	clock      clock.Clock
	ownerToken string
	nextID     uint64
	events     []SandboxEvent
}

func NewSandboxManager(cfg SandboxManagerConfig) *SandboxManager {
	defaults := DefaultSandboxManagerConfig()
	if cfg.Clock == nil {
		cfg.Clock = defaults.Clock
	}
	if cfg.MaxActive <= 0 {
		cfg.MaxActive = defaults.MaxActive
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = defaults.MaxEvents
	}
	m := &SandboxManager{active: make(map[string]*sandboxEntry, cfg.MaxActive), config: cfg, clock: cfg.Clock}
	if strings.TrimSpace(cfg.OwnerToken) != "" {
		m.ownerToken = cfg.OwnerToken
	} else {
		m.ownerToken = observability.RedactIdentifier(fmt.Sprintf("sandbox-owner:%p:%d", m, m.clock.Now().UnixNano()))
	}
	m.events = make([]SandboxEvent, 0, cfg.MaxEvents)
	return m
}

func (m *SandboxManager) Acquire(ctx context.Context, spec SandboxSpec) (*SandboxHandle, error) {
	if m == nil || m.config.Backend == nil || m.config.Leases == nil {
		return nil, ErrSandboxBackendUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec.OwnerToken = m.ownerToken
	m.mu.Lock()
	if spec.ID == "" {
		m.nextID++
		spec.ID = fmt.Sprintf("b4-sandbox-%s-%s-%d", spec.Mode, m.ownerToken, m.nextID)
	}
	if err := spec.Validate(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if len(m.active) >= m.config.MaxActive {
		m.mu.Unlock()
		return nil, fmt.Errorf("discovery sandbox active limit %d reached", m.config.MaxActive)
	}
	if leases, err := m.config.Leases.Load(ctx); err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("inspect sandbox leases: %w", err)
	} else {
		for _, lease := range leases {
			if lease.Spec.ID == spec.ID && lease.Spec.OwnerToken != m.ownerToken {
				m.mu.Unlock()
				return nil, fmt.Errorf("%w: %s", ErrSandboxLeaseCollision, spec.ID)
			}
		}
	}
	for _, entry := range m.active {
		if err := ValidateSandboxIsolation(spec, entry.lease.Spec); err != nil {
			m.mu.Unlock()
			return nil, err
		}
	}
	now := m.clock.Now()
	lease := SandboxLease{Spec: spec, State: SandboxPending, CreatedAt: now, UpdatedAt: now}
	m.active[spec.ID] = &sandboxEntry{lease: lease}
	m.recordEventLocked(lease, "reserved", "")
	m.mu.Unlock()

	if err := m.config.Leases.Save(ctx, lease); err != nil {
		m.removeActive(spec.ID)
		return nil, fmt.Errorf("persist sandbox lease: %w", err)
	}
	if err := m.config.Backend.Apply(ctx, spec); err != nil {
		m.rollback(ctx, lease, err)
		return nil, fmt.Errorf("apply sandbox %s: %w", spec.ID, err)
	}
	readiness, err := m.config.Backend.Readiness(ctx, spec)
	if err != nil {
		m.rollback(ctx, lease, err)
		return nil, fmt.Errorf("check sandbox %s readiness: %w", spec.ID, err)
	}
	if !readiness.Ready || !readiness.OwnerVerified {
		notReadyErr := fmt.Errorf("%w: %s", ErrSandboxNotReady, readiness.Reason)
		m.rollback(ctx, lease, notReadyErr)
		return nil, fmt.Errorf("sandbox %s is not ready: %w", spec.ID, notReadyErr)
	}
	lease.State = SandboxReady
	lease.UpdatedAt = m.clock.Now()
	m.mu.Lock()
	if entry := m.active[spec.ID]; entry != nil {
		entry.lease = lease
	}
	m.recordEventLocked(lease, "ready", "queue-owner-verified")
	m.mu.Unlock()
	if err := m.config.Leases.Save(ctx, lease); err != nil {
		m.rollback(ctx, lease, err)
		return nil, fmt.Errorf("persist ready sandbox lease: %w", err)
	}
	observability.Default().Metrics.Inc(observability.MetricDiscoveryProbe, map[string]string{"sandbox": string(spec.Mode), "verdict": "ready"}, 1)
	return &SandboxHandle{manager: m, id: spec.ID}, nil
}

func (m *SandboxManager) rollback(ctx context.Context, lease SandboxLease, cause error) {
	if cleanupErr := m.config.Backend.Cleanup(ctx, lease.Spec); cleanupErr != nil {
		lease.State = SandboxCleanupFailed
		lease.UpdatedAt = m.clock.Now()
		m.mu.Lock()
		if entry := m.active[lease.Spec.ID]; entry != nil {
			entry.lease = lease
		}
		m.recordEventLocked(lease, "cleanup-failed", cleanupErr.Error())
		m.mu.Unlock()
		_ = m.config.Leases.Save(ctx, lease)
		return
	}
	m.removeActive(lease.Spec.ID)
	_ = m.config.Leases.Delete(ctx, lease.Spec.ID)
	m.recordEvent(lease, "rolled-back", cause.Error())
}

func (m *SandboxManager) removeActive(id string) {
	m.mu.Lock()
	delete(m.active, id)
	m.mu.Unlock()
}

type SandboxHandle struct {
	manager *SandboxManager
	id      string
	once    sync.Once
	err     error
}

func (h *SandboxHandle) ID() string {
	if h == nil {
		return ""
	}
	return h.id
}

func (h *SandboxHandle) Close(ctx context.Context) error {
	if h == nil || h.manager == nil {
		return nil
	}
	h.once.Do(func() { h.err = h.manager.close(ctx, h.id) })
	return h.err
}

func (m *SandboxManager) close(ctx context.Context, id string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	entry := m.active[id]
	if entry == nil {
		m.mu.Unlock()
		return nil
	}
	lease := entry.lease
	lease.State = SandboxClosing
	lease.UpdatedAt = m.clock.Now()
	entry.lease = lease
	m.recordEventLocked(lease, "closing", "")
	m.mu.Unlock()
	if err := m.config.Backend.Cleanup(ctx, lease.Spec); err != nil {
		lease.State = SandboxCleanupFailed
		lease.UpdatedAt = m.clock.Now()
		m.mu.Lock()
		if current := m.active[id]; current != nil {
			current.lease = lease
		}
		m.recordEventLocked(lease, "cleanup-failed", err.Error())
		m.mu.Unlock()
		_ = m.config.Leases.Save(ctx, lease)
		return err
	}
	deleteErr := m.config.Leases.Delete(ctx, id)
	m.mu.Lock()
	delete(m.active, id)
	m.recordEventLocked(lease, "closed", "")
	m.mu.Unlock()
	if deleteErr != nil {
		return fmt.Errorf("delete sandbox lease: %w", deleteErr)
	}
	return nil
}

type SandboxReconcileReport struct {
	Examined int      `json:"examined"`
	Cleaned  int      `json:"cleaned"`
	Retained int      `json:"retained"`
	Errors   []string `json:"errors,omitempty"`
}

// Reconcile only removes leases whose backend explicitly reports stale. An
// unreadable queue is retained and reported; deleting a live/unknown chain is
// more dangerous than leaving a bounded, recoverable lease for the next pass.
func (m *SandboxManager) Reconcile(ctx context.Context) (SandboxReconcileReport, error) {
	var report SandboxReconcileReport
	if m == nil || m.config.Backend == nil || m.config.Leases == nil {
		return report, ErrSandboxBackendUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	leases, err := m.config.Leases.Load(ctx)
	if err != nil {
		return report, err
	}
	for _, lease := range leases {
		if err := lease.Spec.Validate(); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", lease.Spec.ID, err))
			continue
		}
		m.mu.Lock()
		_, active := m.active[lease.Spec.ID]
		m.mu.Unlock()
		if active && lease.Spec.OwnerToken == m.ownerToken {
			continue
		}
		report.Examined++
		readiness, readinessErr := m.config.Backend.Readiness(ctx, lease.Spec)
		if readinessErr != nil {
			report.Retained++
			report.Errors = append(report.Errors, fmt.Sprintf("%s readiness: %v", lease.Spec.ID, readinessErr))
			continue
		}
		if !readiness.Stale {
			report.Retained++
			continue
		}
		if cleanupErr := m.config.Backend.Cleanup(ctx, lease.Spec); cleanupErr != nil {
			report.Retained++
			report.Errors = append(report.Errors, fmt.Sprintf("%s cleanup: %v", lease.Spec.ID, cleanupErr))
			continue
		}
		if deleteErr := m.config.Leases.Delete(ctx, lease.Spec.ID); deleteErr != nil {
			report.Retained++
			report.Errors = append(report.Errors, fmt.Sprintf("%s delete: %v", lease.Spec.ID, deleteErr))
			continue
		}
		report.Cleaned++
		m.recordEvent(lease, "recovered", "stale-owner")
		observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidateRollback, map[string]string{"reason": "stale-sandbox"}, 1)
	}
	return report, nil
}

func (m *SandboxManager) Active() []SandboxLease {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SandboxLease, 0, len(m.active))
	for _, entry := range m.active {
		out = append(out, entry.lease)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Spec.ID < out[j].Spec.ID })
	return out
}

func (m *SandboxManager) Events() []SandboxEvent {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]SandboxEvent(nil), m.events...)
}

func (m *SandboxManager) recordEvent(lease SandboxLease, kind, reason string) {
	m.mu.Lock()
	m.recordEventLocked(lease, kind, reason)
	m.mu.Unlock()
}

func (m *SandboxManager) recordEventLocked(lease SandboxLease, kind, reason string) {
	event := SandboxEvent{Timestamp: m.clock.Now(), SandboxID: observability.RedactIdentifier(lease.Spec.ID), Mode: lease.Spec.Mode, Kind: kind, Reason: reason}
	if len(m.events) == m.config.MaxEvents {
		copy(m.events, m.events[1:])
		m.events = m.events[:m.config.MaxEvents-1]
	}
	m.events = append(m.events, event)
	observability.Default().Trace.Record(observability.TraceEvent{Timestamp: event.Timestamp, FlowID: lease.Spec.ID, Kind: "discovery_sandbox", Fields: map[string]string{"mode": string(lease.Spec.Mode), "event": kind, "reason": reason}})
}

// MemorySandboxLeaseStore is deterministic and useful for unit tests. The
// production target can use FileSandboxLeaseStore to survive process restart.
type MemorySandboxLeaseStore struct {
	mu     sync.Mutex
	max    int
	leases map[string]SandboxLease
}

func NewMemorySandboxLeaseStore(max int) *MemorySandboxLeaseStore {
	if max <= 0 {
		max = 32
	}
	return &MemorySandboxLeaseStore{max: max, leases: make(map[string]SandboxLease, max)}
}

func (s *MemorySandboxLeaseStore) Load(context.Context) ([]SandboxLease, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SandboxLease, 0, len(s.leases))
	for _, lease := range s.leases {
		out = append(out, lease)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Spec.ID < out[j].Spec.ID })
	return out, nil
}

func (s *MemorySandboxLeaseStore) Save(_ context.Context, lease SandboxLease) error {
	if s == nil {
		return ErrSandboxUnknown
	}
	if err := lease.Spec.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.leases[lease.Spec.ID]; !exists && len(s.leases) >= s.max {
		return fmt.Errorf("sandbox lease store limit %d reached", s.max)
	}
	s.leases[lease.Spec.ID] = lease
	return nil
}

func (s *MemorySandboxLeaseStore) Delete(_ context.Context, id string) error {
	if s == nil {
		return ErrSandboxUnknown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.leases, id)
	return nil
}

type FileSandboxLeaseStore struct {
	Path string
	Max  int
	mu   sync.Mutex
}

func (s *FileSandboxLeaseStore) Load(_ context.Context) ([]SandboxLease, error) {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return nil, ErrSandboxUnknown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *FileSandboxLeaseStore) Save(_ context.Context, lease SandboxLease) error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return ErrSandboxUnknown
	}
	if err := lease.Spec.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	leases, err := s.loadLocked()
	if err != nil {
		return err
	}
	found := false
	for i := range leases {
		if leases[i].Spec.ID == lease.Spec.ID {
			leases[i] = lease
			found = true
			break
		}
	}
	if !found {
		if s.Max <= 0 {
			s.Max = 32
		}
		if len(leases) >= s.Max {
			return fmt.Errorf("sandbox lease store limit %d reached", s.Max)
		}
		leases = append(leases, lease)
	}
	return s.writeLocked(leases)
}

func (s *FileSandboxLeaseStore) Delete(_ context.Context, id string) error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return ErrSandboxUnknown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	leases, err := s.loadLocked()
	if err != nil {
		return err
	}
	filtered := leases[:0]
	for _, lease := range leases {
		if lease.Spec.ID != id {
			filtered = append(filtered, lease)
		}
	}
	return s.writeLocked(filtered)
}

func (s *FileSandboxLeaseStore) loadLocked() ([]SandboxLease, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var leases []SandboxLease
	if len(data) > 4*1024*1024 {
		return nil, fmt.Errorf("sandbox lease file exceeds 4 MiB")
	}
	if err := json.Unmarshal(data, &leases); err != nil {
		return nil, err
	}
	if s.Max <= 0 {
		s.Max = 32
	}
	if len(leases) > s.Max {
		return nil, fmt.Errorf("sandbox lease file contains %d leases, max %d", len(leases), s.Max)
	}
	for _, lease := range leases {
		if err := lease.Spec.Validate(); err != nil {
			return nil, fmt.Errorf("lease %s: %w", lease.Spec.ID, err)
		}
	}
	return leases, nil
}

func (s *FileSandboxLeaseStore) writeLocked(leases []SandboxLease) error {
	dir := filepath.Dir(s.Path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".b4-sandbox-lease-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	data, err := json.Marshal(leases)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.Path)
}
