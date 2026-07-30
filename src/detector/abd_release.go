package detector

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type DetectorCapacityProfile struct {
	MaxConcurrent  int
	MaxPackets     uint64
	MaxUniqueBytes uint64
	Calibrated     bool
	Source         string
	CalibratedAt   time.Time
}

func SafeStaticCapacity() DetectorCapacityProfile {
	return DetectorCapacityProfile{MaxConcurrent: 2, MaxPackets: 2000, MaxUniqueBytes: 4 << 20, Source: "static-safe-fallback"}
}
func CalibrateCapacity(observedDrops uint64, observedLatency time.Duration, now time.Time) DetectorCapacityProfile {
	p := SafeStaticCapacity()
	if observedDrops == 0 && observedLatency < 500*time.Millisecond {
		p.MaxConcurrent = 4
		p.Calibrated = true
		p.Source = "field-calibration"
		p.CalibratedAt = now
	}
	return p
}

type DeepCheckpoint struct {
	RunID            string
	Scope            monitor.MonitorScopeKey
	ConfigGeneration uint64
	NetworkContextID string
	NextTarget       int
	EvidenceRefs     []string
	Complete         bool
	SavedAt          time.Time
}

func (c DeepCheckpoint) Compatible(scope monitor.MonitorScopeKey, now time.Time) bool {
	return c.RunID != "" && c.Scope == scope && c.ConfigGeneration == scope.ConfigGeneration && c.NetworkContextID == scope.NetworkContextID && !c.Complete && !c.SavedAt.IsZero() && now.Sub(c.SavedAt) < 30*time.Minute
}

type HandoffGuard struct {
	mu        sync.Mutex
	delivered map[string]MonitorDiagnosticResult
}

func NewHandoffGuard() *HandoffGuard {
	return &HandoffGuard{delivered: map[string]MonitorDiagnosticResult{}}
}
func (g *HandoffGuard) Deliver(result MonitorDiagnosticResult, expectedAssessment, expectedRequest string, scope monitor.MonitorScopeKey) (bool, error) {
	if g == nil || !result.Valid() || result.AssessmentID != expectedAssessment || result.RequestID != expectedRequest || result.Scope != scope || result.ConfigGeneration != scope.ConfigGeneration {
		return false, errors.New("monitor result identity or generation mismatch")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key := result.AssessmentID + "|" + result.RequestID + "|" + strconv.FormatUint(result.ConfigGeneration, 10)
	if old, ok := g.delivered[key]; ok {
		if old.ResultID == result.ResultID {
			return true, nil
		}
		return false, errors.New("conflicting duplicate monitor result")
	}
	g.delivered[key] = result
	return true, nil
}

type ABDReleaseGate struct {
	DetectorTestsPassed     bool
	MonitorAdapterReady     bool
	ClientResolutionReady   bool
	MultiVantageReady       bool
	CapacitySafe            bool
	ExternalRouterValidated bool
	AndroidValidated        bool
	PrivacyValidated        bool
	DirectApplyDisabled     bool
}

func (g ABDReleaseGate) Verdict() string {
	if g.DetectorTestsPassed && g.MonitorAdapterReady && g.ClientResolutionReady && g.MultiVantageReady && g.CapacitySafe && g.ExternalRouterValidated && g.AndroidValidated && g.PrivacyValidated && g.DirectApplyDisabled {
		return "ABD_PRODUCTION_READY"
	}
	return "ABD_FIELD_VALIDATION_PENDING"
}
