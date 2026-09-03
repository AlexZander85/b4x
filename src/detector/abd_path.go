package detector

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
)

type ProbePathMode string

const (
	PathNativeDirect ProbePathMode = "native-direct"
	PathProduction   ProbePathMode = "production"
	PathCandidate    ProbePathMode = "candidate"
	PathTransport    ProbePathMode = "transport"
)

type ReferencePathSpec struct {
	ObserverID       string
	Mode             ProbePathMode
	NetworkContextID string
	RedactionKeyID   string
	RequiredStages   []string
}
type ObserverCapability struct {
	ObserverID string
	Stages     []string
	Protocols  []string
	IPFamilies []string
	Healthy    bool
	ObservedAt time.Time
	ExpiresAt  time.Time
}

func (c ObserverCapability) Fresh(now time.Time) bool {
	return c.ObserverID != "" && c.Healthy && !c.ObservedAt.IsZero() && (c.ExpiresAt.IsZero() || now.Before(c.ExpiresAt))
}

// SupportsStage reports whether the observer capability declares the
// vantage stage needed for the hypothesis under evaluation (FB-30). A
// TCP/TLS-only observer (Stages: tcp,tls) must never be used to confirm an
// HTTP/body hypothesis: the capability gate is stage-aware and fails
// closed.
func (c ObserverCapability) SupportsStage(stage VantageStage) bool {
	return c.ObserverID != "" && hasString(c.Stages, string(stage))
}

func hasString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

type ObserverHealthLease struct {
	ObserverID, LeaseID   string
	AcquiredAt, ExpiresAt time.Time
	Capability            ObserverCapability
}

func (l ObserverHealthLease) Valid(now time.Time) bool {
	return l.ObserverID != "" && l.LeaseID != "" && l.Capability.Fresh(now) && !now.Before(l.AcquiredAt) && (l.ExpiresAt.IsZero() || now.Before(l.ExpiresAt))
}

type ProbeContext struct {
	Scope             monitor.MonitorScopeKey
	Mode              ProbePathMode
	BudgetToken       string
	RequestExpiry     time.Time
	MonitorGeneration uint64
	SelfInterference  bool
}

func (c ProbeContext) Valid(now time.Time) bool {
	return c.Scope.Valid() && c.Mode != "" && c.BudgetToken != "" && c.MonitorGeneration == c.Scope.ConfigGeneration && !c.RequestExpiry.IsZero() && now.Before(c.RequestExpiry) && !c.SelfInterference
}

type VantageStage string

const (
	StageTCP  VantageStage = "tcp"
	StageTLS  VantageStage = "tls"
	StageHTTP VantageStage = "http"
	StageBody VantageStage = "body"
	StageQUIC VantageStage = "quic"
)

type VantageObservation struct {
	ObserverID    string
	TargetID      string
	Stage         VantageStage
	ExactEndpoint bool
	Available     bool
	Success       bool
	ObservedAt    time.Time
	Capability    ObserverCapability
}

// VantageOpinion is the machine-readable verdict of one observer about a
// local probe outcome (FB-30). An observer that is unavailable, stale, or
// lacking the stage-aware capability for the hypothesis must answer
// NO_OPINION — never a target-failure claim.
type VantageOpinion string

const (
	VantageNoOpinion    VantageOpinion = "NO_OPINION"
	VantageCorroborates VantageOpinion = "CORROBORATES"
	VantageContradicts  VantageOpinion = "CONTRADICTS"
)

// MultiVantageComparison aggregates one local outcome with one observer
// outcome. Stage alignment and exact-vs-independent mode are validated
// here, and the observer's stage-aware capability is required for a
// corroborating opinion: a TCP/TLS-only observer cannot confirm an HTTP or
// body hypothesis.
type MultiVantageComparison struct {
	TargetID                         string
	Stage                            VantageStage
	ExactEndpoint                    bool
	LocalSuccess, LocalFailure       bool
	ObserverSuccess, ObserverFailure bool
	ObserverOpinion                  bool
	Opinion                          VantageOpinion
	CapabilitySupported              bool
	Explanation                      string
}

func CompareVantage(local VantageObservation, observer VantageObservation, now time.Time) MultiVantageComparison {
	r := MultiVantageComparison{TargetID: local.TargetID, Stage: local.Stage, ExactEndpoint: local.ExactEndpoint, Opinion: VantageNoOpinion}
	r.LocalSuccess = local.Available && local.Success
	r.LocalFailure = local.Available && !local.Success
	// Observer unavailable must never produce a target-failure claim: it
	// yields NO_OPINION (FB-30).
	if !observer.Available {
		r.Explanation = "observer unavailable; no opinion"
		return r
	}
	// Identity and exact-vs-independent mode must be aligned: exact-endpoint
	// evidence must never be conflated with independent-resolution evidence.
	if observer.TargetID != local.TargetID || observer.ExactEndpoint != local.ExactEndpoint {
		RecordMultiVantageViolation(violationExactEndpointServiceResolutionConflated, local, observer)
		r.Explanation = "observer target/mode mismatch; no opinion"
		return r
	}
	// Stage alignment is required for a corroborating opinion.
	if observer.Stage != local.Stage {
		RecordMultiVantageViolation(violationStageMismatch, local, observer)
		r.Explanation = "observer stage mismatch; no opinion"
		return r
	}
	// Stage-aware capability gate: a TCP/TLS-only observer must never be
	// used to confirm an HTTP/body hypothesis (FB-30).
	if !observer.Capability.Fresh(now) {
		RecordMultiVantageViolation(violationObserverCapabilityUnproven, local, observer)
		r.Explanation = "observer capability stale or unhealthy; no opinion"
		return r
	}
	if !observer.Capability.SupportsStage(local.Stage) {
		if local.Stage == StageHTTP || local.Stage == StageBody {
			RecordMultiVantageViolation(violationHTTPHypothesisFromTCPTLSOnly, local, observer)
		} else {
			RecordMultiVantageViolation(violationObserverCapabilityUnproven, local, observer)
		}
		r.Explanation = "observer capability does not cover stage; no opinion"
		return r
	}
	r.CapabilitySupported = true
	r.ObserverOpinion = true
	r.ObserverSuccess = observer.Success
	r.ObserverFailure = !observer.Success
	if r.LocalFailure && r.ObserverSuccess {
		r.Opinion = VantageContradicts
		r.Explanation = "observer-only success; local-only failure"
	} else if r.LocalSuccess && r.ObserverFailure {
		r.Opinion = VantageContradicts
		r.Explanation = "observer-only failure; no host-dead claim"
	} else if r.LocalFailure && r.ObserverFailure {
		r.Opinion = VantageCorroborates
		r.Explanation = "stage-aligned corroborated failure"
	} else {
		r.Opinion = VantageCorroborates
		r.Explanation = "stage-aligned observer comparison"
	}
	return r
}

var ErrInvalidProbeContext = errors.New("invalid clean probe context")

func ValidateProbeContext(c ProbeContext, now time.Time) error {
	if !c.Valid(now) {
		return ErrInvalidProbeContext
	}
	return nil
}

// vantageViolationKind identifies one FB-30 multi-vantage hard-gate
// violation. Every violation fires the mon + abd counter pair through one
// call site (the same pattern as RecordResolutionErasure in FB-29).
type vantageViolationKind string

const (
	// violationHTTPHypothesisFromTCPTLSOnly: a TCP/TLS-only observer was
	// asked to confirm an HTTP/body hypothesis.
	violationHTTPHypothesisFromTCPTLSOnly vantageViolationKind = "http_hypothesis_from_tcp_tls_only_observer"
	// violationObserverUnavailableAsFailure: an unavailable observer was
	// treated as a target-failure claim instead of NO_OPINION.
	violationObserverUnavailableAsFailure vantageViolationKind = "observer_unavailable_as_target_failure"
	// violationExactEndpointServiceResolutionConflated: exact-endpoint and
	// independent-resolution evidence were conflated.
	violationExactEndpointServiceResolutionConflated vantageViolationKind = "exact_endpoint_service_resolution_conflated"
	// violationObserverCapabilityUnproven: an observer whose stage-aware
	// capability was not fresh/proven was used for a corroborating opinion.
	violationObserverCapabilityUnproven vantageViolationKind = "observer_capability_unproven"
	// violationStageMismatch: observer stage did not match the hypothesis
	// stage.
	violationStageMismatch vantageViolationKind = "multivantage_stage_mismatch"
)

// RecordMultiVantageViolation is the hard-gate producer call site for the
// FB-30 multi-vantage zero-tolerance counters (owner families mon/abd,
// GlobalGateClass "multi_vantage"). It fires the mon + abd counter pair
// for the same violation kind, mirroring FB-29's RecordResolutionErasure
// pattern. The call sites live in CompareVantage: every rejection path is
// recorded exactly when the anti-rule would otherwise have produced a
// target-failure or conflated claim.
func RecordMultiVantageViolation(kind vantageViolationKind, local VantageObservation, observer VantageObservation) {
	labels := map[string]string{
		"observer": observability.RedactIdentifier(observer.ObserverID),
		"target":   observability.RedactIdentifier(local.TargetID),
		"stage":    string(local.Stage),
	}
	switch kind {
	case violationHTTPHypothesisFromTCPTLSOnly:
		observability.Default().Metrics.Inc(observability.MetricMonitorHttpHypothesisFromTCPTLSOnlyObserver, labels, 1)
		observability.Default().Metrics.Inc(observability.MetricDetectorHttpHypothesisFromTCPTLSOnlyObserver, labels, 1)
	case violationExactEndpointServiceResolutionConflated:
		observability.Default().Metrics.Inc(observability.MetricMonitorExactEndpointServiceResolutionConflated, labels, 1)
		observability.Default().Metrics.Inc(observability.MetricDetectorExactEndpointServiceResolutionConflated, labels, 1)
	case violationObserverCapabilityUnproven:
		observability.Default().Metrics.Inc(observability.MetricMonitorObserverCapabilityUnproven, labels, 1)
		observability.Default().Metrics.Inc(observability.MetricDetectorObserverCapabilityUnproven, labels, 1)
	case violationObserverUnavailableAsFailure:
		observability.Default().Metrics.Inc(observability.MetricMonitorObserverUnavailableAsTargetFailure, labels, 1)
		observability.Default().Metrics.Inc(observability.MetricDetectorObserverUnavailableAsTargetFailure, labels, 1)
	case violationStageMismatch:
		observability.Default().Metrics.Inc(observability.MetricDetectorMultiVantageStageMismatch, labels, 1)
		// monitor side has no stage-mismatch counterpart; the detector
		// counter is the monitor of the rule.
	}
}
