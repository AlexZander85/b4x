package monitor

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// BehavioralFingerprintSummary is the bounded, privacy-safe projection of
// behavioral evidence exposed by the existing monitoring status API. It
// deliberately excludes raw domains/SNI, client addresses, payload bytes and
// packet captures; the authoritative evidence remains owned by detector.
type BehavioralFingerprintSummary struct {
	EvidenceID        string    `json:"evidence_id"`
	PanelHash         string    `json:"panel_hash"`
	FeatureVectorHash string    `json:"feature_vector_hash"`
	Confidence        float64   `json:"confidence"`
	NoiseScore        float64   `json:"noise_score"`
	ConclusiveCount   uint16    `json:"conclusive_count"`
	InconclusiveCount uint16    `json:"inconclusive_count"`
	CreatedAt         time.Time `json:"created_at"`
	ValidUntil        time.Time `json:"valid_until,omitempty"`
}

type MonitorStatus struct {
	SchemaVersion uint16
	Scope         MonitorScopeKey
	Health        HealthState
	Visibility    VisibilityState
	Suppressed    bool
	Suppressors   []SuppressorReason
	QueuedQuick   int
	QueuedDeep    int
	RunningQuick  int
	RunningDeep   int

	// AFS extends the existing read model instead of adding another status
	// service/endpoint. BehavioralFingerprint is an evidence summary only;
	// AdaptiveSynthesis is lifecycle metadata only and carries no apply
	// authority or packet program.
	BehavioralFingerprint *BehavioralFingerprintSummary `json:"behavioral_fingerprint,omitempty"`
	AdaptiveSynthesis     AdaptiveSynthesisStatus       `json:"adaptive_synthesis"`

	UpdatedAt time.Time
}

type MonitorAPIProjection struct {
	mu         sync.RWMutex
	status     map[string]MonitorStatus
	correlator *FlowCorrelator
}

func NewMonitorAPIProjection() *MonitorAPIProjection {
	return &MonitorAPIProjection{status: map[string]MonitorStatus{}, correlator: NewFlowCorrelator()}
}
func (p *MonitorAPIProjection) Update(s MonitorStatus) {
	if p == nil || !s.Scope.Valid() {
		return
	}
	if p.correlator != nil {
		p.correlator.EnsureScope(s.Scope)
		p.correlator.ObserveHealth(s.Scope, "", s.Health, s.UpdatedAt)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := correlationKey(s.Scope)
	current := p.status[key]
	// Ordinary MON/ABD projection updates must not erase an active AFS status
	// or already-published behavioral fingerprint summary.
	if s.AdaptiveSynthesis.State == "" && current.AdaptiveSynthesis.State != "" {
		s.AdaptiveSynthesis = current.AdaptiveSynthesis
	}
	if s.BehavioralFingerprint == nil && current.BehavioralFingerprint != nil {
		copySummary := *current.BehavioralFingerprint
		s.BehavioralFingerprint = &copySummary
	}
	p.status[key] = cloneMonitorStatus(s)
}
func (p *MonitorAPIProjection) Get(scope MonitorScopeKey) (MonitorStatus, bool) {
	if p == nil {
		return MonitorStatus{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	s, ok := p.status[correlationKey(scope)]
	return cloneMonitorStatus(s), ok
}
func (p *MonitorAPIProjection) List() []MonitorStatus {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]MonitorStatus, 0, len(p.status))
	for _, s := range p.status {
		out = append(out, cloneMonitorStatus(s))
	}
	return out
}

func (p *MonitorAPIProjection) Correlator() *FlowCorrelator {
	if p == nil {
		return nil
	}
	return p.correlator
}

// PatchAdaptiveSynthesis updates only the AFS lifecycle projection while
// preserving the existing health/visibility/queue status for the scope.
func (p *MonitorAPIProjection) PatchAdaptiveSynthesis(scope MonitorScopeKey, status AdaptiveSynthesisStatus, now time.Time) {
	if p == nil || !scope.Valid() {
		return
	}
	if p.correlator != nil {
		p.correlator.EnsureScope(scope)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := correlationKey(scope)
	current := p.status[key]
	current.SchemaVersion = SchemaVersion
	current.Scope = scope
	current.AdaptiveSynthesis = status
	current.AdaptiveSynthesis.Reasons = append([]string(nil), status.Reasons...)
	current.UpdatedAt = now
	p.status[key] = current
}

// PatchBehavioralFingerprint updates only the privacy-safe behavioral summary
// for the existing monitor scope.
func (p *MonitorAPIProjection) PatchBehavioralFingerprint(scope MonitorScopeKey, summary *BehavioralFingerprintSummary, now time.Time) {
	if p == nil || !scope.Valid() {
		return
	}
	if p.correlator != nil {
		p.correlator.EnsureScope(scope)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := correlationKey(scope)
	current := p.status[key]
	current.SchemaVersion = SchemaVersion
	current.Scope = scope
	if summary == nil {
		current.BehavioralFingerprint = nil
	} else {
		copySummary := *summary
		current.BehavioralFingerprint = &copySummary
	}
	current.UpdatedAt = now
	p.status[key] = current
}

func cloneMonitorStatus(s MonitorStatus) MonitorStatus {
	s.Suppressors = append([]SuppressorReason(nil), s.Suppressors...)
	s.AdaptiveSynthesis.Reasons = append([]string(nil), s.AdaptiveSynthesis.Reasons...)
	if s.BehavioralFingerprint != nil {
		copySummary := *s.BehavioralFingerprint
		s.BehavioralFingerprint = &copySummary
	}
	return s
}

// LegacyWatchdogAdapter keeps old status/force-check callers alive while
// ensuring the old applier is not reachable from the compatibility surface.
type LegacyWatchdogAdapter struct {
	scheduler  *DiagnosticScheduler
	projection *MonitorAPIProjection
}

func NewLegacyWatchdogAdapter(s *DiagnosticScheduler, p *MonitorAPIProjection) *LegacyWatchdogAdapter {
	return &LegacyWatchdogAdapter{scheduler: s, projection: p}
}
func (a *LegacyWatchdogAdapter) Status(scope MonitorScopeKey) (MonitorStatus, bool) {
	if a == nil || a.projection == nil {
		return MonitorStatus{}, false
	}
	return a.projection.Get(scope)
}
func (a *LegacyWatchdogAdapter) ForceCheck(scope MonitorScopeKey, requestID string, now time.Time) error {
	if a == nil || a.scheduler == nil || requestID == "" || !scope.Valid() {
		return errors.New("invalid legacy force-check")
	}
	return a.scheduler.Enqueue(DiagnosticRequest{RequestID: requestID, IdempotencyKey: "watchdog/" + requestID, Scope: scope, Kind: DiagnosticQuick, Reason: "legacy-force-check", RequestedAt: now}, now)
}

type MonitorCheckpoint struct {
	SchemaVersion  uint16
	SavedAt        time.Time
	CutoverVersion string
	Statuses       []MonitorStatus
}

func (c MonitorCheckpoint) Valid() bool {
	return c.SchemaVersion == SchemaVersion && !c.SavedAt.IsZero() && c.CutoverVersion != ""
}
func EncodeCheckpoint(c MonitorCheckpoint) ([]byte, error) {
	if !c.Valid() {
		return nil, errors.New("invalid monitor checkpoint")
	}
	return json.Marshal(c)
}
func DecodeCheckpoint(b []byte) (MonitorCheckpoint, error) {
	var c MonitorCheckpoint
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if !c.Valid() {
		return c, errors.New("invalid monitor checkpoint")
	}
	return c, nil
}
