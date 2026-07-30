// Package silentpath owns the evidence-only model for silent path failures.
// It does not authorize packet mutation, routing or transport changes.
package silentpath

import (
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

type FailureClass string

const (
	FailureBeforeServerHello  FailureClass = "before-server-hello"
	FailureAfterServerHello   FailureClass = "after-server-hello"
	FailureEarlyBody          FailureClass = "early-body"
	FailureMidstream          FailureClass = "midstream"
	FailureThroughputCollapse FailureClass = "throughput-collapse"
	FailureTransportPath      FailureClass = "transport-path"
)

type Confidence string

const (
	ConfidenceNone         Confidence = "none"
	ConfidenceSuspicion    Confidence = "suspicion"
	ConfidenceCorrelated   Confidence = "correlated"
	ConfidenceDifferential Confidence = "differential"
	ConfidenceRecurrent    Confidence = "recurrent-validated"
)

// ReasonCode is a stable non-attributing explanation for diagnostics.
type ReasonCode string

const (
	ReasonNoUniqueProgress        ReasonCode = "no_unique_progress"
	ReasonRetryObserved           ReasonCode = "retry_observed"
	ReasonRetransmissionBurst     ReasonCode = "retransmission_burst"
	ReasonExplicitServerResponse  ReasonCode = "explicit_server_response"
	ReasonFreshScopeSuccess       ReasonCode = "fresh_same_scope_success"
	ReasonCompatiblePathSuccess   ReasonCode = "fresh_compatible_path_success"
	ReasonLikelyParallel          ReasonCode = "likely_parallel_or_prefetch"
	ReasonVisibilityIncomplete    ReasonCode = "visibility_incomplete"
	ReasonResourcePressure        ReasonCode = "resource_pressure"
	ReasonClassificationAmbiguous ReasonCode = "classification_ambiguous"
	ReasonControlUnhealthy        ReasonCode = "control_unhealthy"
	ReasonFlowTooYoung            ReasonCode = "flow_below_minimum_grace"
)

type Scope struct {
	ClientKey     classifier.ClientKey
	SetID         string
	ComponentID   string
	DomainKey     string
	ConfigGen     uint64
	IPFamily      uint8
	TransportPath string
}

// ValidForRecovery makes the destination-only prohibition executable.
func (s Scope) ValidForRecovery(auth classifier.ActionAuthorization) bool {
	return !s.ClientKey.IsZero() && s.ClientKey == auth.Client &&
		strings.TrimSpace(s.SetID) != "" && s.SetID == auth.SetID &&
		strings.TrimSpace(s.ComponentID) != "" && strings.TrimSpace(s.DomainKey) != "" &&
		s.DomainKey == auth.Domain && s.ConfigGen != 0 && s.ConfigGen == auth.ConfigGen &&
		s.IPFamily != 0 && strings.TrimSpace(s.TransportPath) != "" && auth.Final
}

type Evidence struct {
	Kind              ReasonCode
	Source            string
	FlowKey           classifier.FlowKey
	Scope             Scope
	ObservedAt        time.Time
	ExpiresAt         time.Time
	Weight            int
	IndependentFamily string
	Details           map[string]string
}

func (e Evidence) Expired(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt)
}

type Assessment struct {
	Class             FailureClass
	Scope             Scope
	Confidence        Confidence
	PositiveEvidence  []Evidence
	Suppressors       []Evidence
	DifferentialRunID string
	RecoveryAllowed   bool
	ReasonCode        ReasonCode
}

// ObserveAssessment cannot create a route or packet action.
func ObserveAssessment(class FailureClass, scope Scope, reason ReasonCode) Assessment {
	return Assessment{Class: class, Scope: scope, Confidence: ConfidenceSuspicion, ReasonCode: reason, RecoveryAllowed: false}
}
