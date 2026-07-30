package detector

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
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
type MultiVantageComparison struct {
	TargetID                         string
	Stage                            VantageStage
	ExactEndpoint                    bool
	LocalSuccess, LocalFailure       bool
	ObserverSuccess, ObserverFailure bool
	ObserverOpinion                  bool
	Explanation                      string
}

func CompareVantage(local VantageObservation, observer VantageObservation, now time.Time) MultiVantageComparison {
	r := MultiVantageComparison{TargetID: local.TargetID, Stage: local.Stage, ExactEndpoint: local.ExactEndpoint}
	r.LocalSuccess = local.Available && local.Success
	r.LocalFailure = local.Available && !local.Success
	if observer.Available && observer.Capability.Fresh(now) && observer.TargetID == local.TargetID && observer.Stage == local.Stage && observer.ExactEndpoint == local.ExactEndpoint {
		r.ObserverOpinion = true
		r.ObserverSuccess = observer.Success
		r.ObserverFailure = !observer.Success
		if r.LocalFailure && r.ObserverSuccess {
			r.Explanation = "local-only failure; observer contradicts reachability"
		} else if r.LocalSuccess && r.ObserverFailure {
			r.Explanation = "observer-only failure; no host-dead claim"
		} else {
			r.Explanation = "stage-aligned observer comparison"
		}
	} else {
		r.Explanation = "observer unavailable or stage/identity mismatch; no opinion"
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
