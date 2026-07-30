package detector

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type ResolutionExperimentMode string

const (
	ExactClientResolution        ResolutionExperimentMode = "exact-client-resolution"
	IndependentCurrentResolution ResolutionExperimentMode = "independent-current-resolution"
)

type DNSAddressOutcome struct {
	SnapshotID   string
	IPHash       string
	IPFamily     string
	AddressIndex uint16
	QueryStage   string
	Success      bool
	FailureCode  ProbeFailureCode
	Attribution  monitor.FailureAttribution
	ObservedAt   time.Time
}
type DNSDifferentialEvidence struct {
	Scope                 monitor.MonitorScopeKey
	ClientSnapshotID      string
	IndependentSnapshotID string
	ClientQNameHash       string
	CNAMEChain            []string
	ClientAnswers         []monitor.ResolvedEndpoint
	IndependentAnswers    []monitor.ResolvedEndpoint
	Outcomes              []DNSAddressOutcome
	StaleClientSnapshot   bool
	MismatchedGeneration  bool
	CreatedAt             time.Time
}

type ProbeFailureCode string

const (
	FailureDNSNoAnswer         ProbeFailureCode = "dns-no-answer"
	FailureDNSMismatch         ProbeFailureCode = "dns-mismatch"
	FailureDNSTimeout          ProbeFailureCode = "dns-timeout"
	FailureTransportTimeout    ProbeFailureCode = "transport-timeout"
	FailureTLSAlert            ProbeFailureCode = "tls-alert"
	FailureHTTPBlockPage       ProbeFailureCode = "http-block-page"
	FailureBodyStall           ProbeFailureCode = "body-stall"
	FailureObserverUnavailable ProbeFailureCode = "observer-unavailable"
)

func BuildDNSDifferential(scope monitor.MonitorScopeKey, client, independent monitor.ClientResolutionSnapshot, outcomes []DNSAddressOutcome, now time.Time) (DNSDifferentialEvidence, error) {
	if !scope.Valid() || client.SnapshotID == "" || client.NetworkContextID != scope.NetworkContextID || client.ConfigGeneration != scope.ConfigGeneration || client.ValidUntil.IsZero() {
		return DNSDifferentialEvidence{}, errors.New("invalid client resolution binding")
	}
	r := DNSDifferentialEvidence{Scope: scope, ClientSnapshotID: client.SnapshotID, ClientQNameHash: client.OriginalQNameHash, CNAMEChain: append([]string(nil), client.CNAMEChainHashes...), ClientAnswers: append([]monitor.ResolvedEndpoint(nil), client.Answers...), CreatedAt: now}
	if !now.Before(client.ValidUntil) {
		r.StaleClientSnapshot = true
	}
	if independent.SnapshotID != "" {
		r.IndependentSnapshotID = independent.SnapshotID
		r.IndependentAnswers = append([]monitor.ResolvedEndpoint(nil), independent.Answers...)
	}
	if independent.ConfigGeneration != 0 && independent.ConfigGeneration != scope.ConfigGeneration {
		r.MismatchedGeneration = true
	}
	r.Outcomes = append([]DNSAddressOutcome(nil), outcomes...)
	return r, nil
}

func (e DNSDifferentialEvidence) Valid() bool {
	return e.Scope.Valid() && e.ClientSnapshotID != "" && !e.MismatchedGeneration && len(e.ClientAnswers) > 0 && len(e.Outcomes) > 0
}
func (e DNSDifferentialEvidence) OutcomeVector() []DNSAddressOutcome {
	return append([]DNSAddressOutcome(nil), e.Outcomes...)
}
