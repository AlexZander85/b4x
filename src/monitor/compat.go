package monitor

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type MonitorStatus struct {
	SchemaVersion uint16
	Scope         MonitorScopeKey
	Health        HealthState
	Visibility    VisibilityState
	Suppressed    bool
	Suppressors   []SuppressorReason
	QueuedQuick   int
	QueuedDeep    int
	UpdatedAt     time.Time
}

type MonitorAPIProjection struct {
	mu     sync.RWMutex
	status map[string]MonitorStatus
}

func NewMonitorAPIProjection() *MonitorAPIProjection {
	return &MonitorAPIProjection{status: map[string]MonitorStatus{}}
}
func (p *MonitorAPIProjection) Update(s MonitorStatus) {
	if p == nil || !s.Scope.Valid() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status[correlationKey(s.Scope)] = s
}
func (p *MonitorAPIProjection) Get(scope MonitorScopeKey) (MonitorStatus, bool) {
	if p == nil {
		return MonitorStatus{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	s, ok := p.status[correlationKey(scope)]
	s.Suppressors = append([]SuppressorReason(nil), s.Suppressors...)
	return s, ok
}
func (p *MonitorAPIProjection) List() []MonitorStatus {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]MonitorStatus, 0, len(p.status))
	for _, s := range p.status {
		s.Suppressors = append([]SuppressorReason(nil), s.Suppressors...)
		out = append(out, s)
	}
	return out
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
