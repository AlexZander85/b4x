package monitor

import (
	"errors"
	"sync"
	"time"
)

type DiagnosticRunState string

const (
	RunRequested  DiagnosticRunState = "requested"
	RunRunning    DiagnosticRunState = "running"
	RunCompleted  DiagnosticRunState = "completed"
	RunPartial    DiagnosticRunState = "partial"
	RunCancelled  DiagnosticRunState = "cancelled"
	RunSuppressed DiagnosticRunState = "suppressed"
)

type TargetPlanOverlay struct {
	Scope                MonitorScopeKey
	ResolutionSnapshotID string
	TargetHashes         []string
	ControlHashes        []string
	RequiredSources      []ObservationSource
	VisibilitySnapshotID string
	ConfigGeneration     uint64
}

func (p TargetPlanOverlay) Valid() bool {
	return p.Scope.Valid() && p.ResolutionSnapshotID != "" && p.VisibilitySnapshotID != "" && p.ConfigGeneration == p.Scope.ConfigGeneration && len(p.TargetHashes) > 0
}

type MonitorDiagnosticRequest struct {
	RequestID       string
	Lease           DiagnosticLease
	Overlay         TargetPlanOverlay
	TriggerReason   string
	RequestedAt     time.Time
	ResolutionFresh bool
	VisibilityFresh bool
}

func (r MonitorDiagnosticRequest) Valid(now time.Time) bool {
	return r.RequestID != "" && r.Lease.LeaseID != "" && r.Overlay.Valid() && r.ResolutionFresh && r.VisibilityFresh && (r.RequestedAt.IsZero() || !now.Before(r.RequestedAt))
}

type ABDRun struct {
	RunID         string
	Request       MonitorDiagnosticRequest
	State         DiagnosticRunState
	StartedAt     time.Time
	FinishedAt    time.Time
	EvidenceRef   []string
	Complete      bool
	Authoritative bool
}

type ABDResult struct {
	RunID         string
	EvidenceRefs  []string
	Complete      bool
	Authoritative bool
	Scope         MonitorScopeKey
}

type ABDEscalationAdapter struct {
	mu   sync.Mutex
	runs map[string]*ABDRun
	seq  uint64
}

func NewABDEscalationAdapter() *ABDEscalationAdapter {
	return &ABDEscalationAdapter{runs: map[string]*ABDRun{}}
}

var ErrInvalidDiagnosticRequest = errors.New("invalid monitor diagnostic request")
var ErrRunNotFound = errors.New("abd run not found")

func (a *ABDEscalationAdapter) Begin(req MonitorDiagnosticRequest, now time.Time) (ABDRun, error) {
	if a == nil || !req.Valid(now) {
		return ABDRun{}, ErrInvalidDiagnosticRequest
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	id := req.RequestID + "/abd-" + itoa(a.seq)
	run := &ABDRun{RunID: id, Request: req, State: RunRunning, StartedAt: now}
	a.runs[id] = run
	return *run, nil
}

func itoa(n uint64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}

func (a *ABDEscalationAdapter) Complete(result ABDResult, now time.Time) (ABDRun, error) {
	if a == nil {
		return ABDRun{}, ErrRunNotFound
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.runs[result.RunID]
	if r == nil {
		return ABDRun{}, ErrRunNotFound
	}
	if result.Scope != r.Request.Overlay.Scope {
		return ABDRun{}, errors.New("abd scope mismatch")
	}
	r.FinishedAt = now
	r.EvidenceRef = append([]string(nil), result.EvidenceRefs...)
	r.Complete = result.Complete
	r.Authoritative = result.Authoritative
	if result.Authoritative && result.Complete && len(result.EvidenceRefs) > 0 {
		r.State = RunCompleted
	} else {
		r.State = RunPartial
		r.Authoritative = false
		r.Complete = false
	}
	return *r, nil
}

func (a *ABDEscalationAdapter) Cancel(runID string, now time.Time) (ABDRun, error) {
	if a == nil {
		return ABDRun{}, ErrRunNotFound
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.runs[runID]
	if r == nil {
		return ABDRun{}, ErrRunNotFound
	}
	if r.State == RunRunning {
		r.State = RunCancelled
		r.FinishedAt = now
	}
	return *r, nil
}

func (a *ABDEscalationAdapter) Snapshot(runID string) (ABDRun, bool) {
	if a == nil {
		return ABDRun{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.runs[runID]
	if !ok {
		return ABDRun{}, false
	}
	r.EvidenceRef = append([]string(nil), r.EvidenceRef...)
	return *r, true
}
