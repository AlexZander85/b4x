package detector

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type ResolutionExperimentMode string

const (
	// ClientObservedExactEndpoint is the machine-readable kind for the
	// "client_observed_exact_endpoint" experiment (FB-29): the terminal
	// endpoint(s) an actual client resolver selected and their per-address
	// proof results. The kind string is canonical and consumed verbatim by
	// the evidence API and hard-gate registry.
	ClientObservedExactEndpoint ResolutionExperimentMode = "client_observed_exact_endpoint"

	// IndependentCurrentResolution is the machine-readable kind for the
	// "independent_current_resolution" experiment (FB-29): the recursive
	// resolver's current authoritative-answers view taken independently of
	// the client-side cached snapshot.
	IndependentCurrentResolution ResolutionExperimentMode = "independent_current_resolution"

	// Deprecated aliases kept for callers that referenced the pre-FB-29
	// spellings; the canonical machine-readable kinds above must be used in
	// evidence payloads.
	ExactClientResolution                                = ClientObservedExactEndpoint
	LegacyIndependentResolution ResolutionExperimentMode = "independent-current-resolution"
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

	// FB-29 terminal per-address A/AAAA outcome fields. Each entry
	// describes one concrete endpoint a resolution experiment reached, with
	// machine-readable provenance, selected state, per-protocol stage
	// results, latency, attribution and evidence refs.
	Experiment    ResolutionExperimentMode
	Provenance    string
	Selected      bool
	StageOutcomes []AddressStageOutcome // dns, tcp, tls, http, quic
	LatencyMS     uint32
	EvidenceRefs  []string
}

// AddressStageOutcome is a per-protocol stage verdict for a single address,
// ordered from DNS to QUIC. Every protocol result stays explicit so the
// selection of one working address cannot erase a failed sibling.
type AddressStageOutcome struct {
	Protocol  string // dns | tcp | tls | http | quic
	Outcome   string // ok | timeout | refused | blocked | reset | bad-cert | incomplete
	LatencyMS uint32
}

// Machine-readable stage protocols and outcome values (stable, consumed by
// the evidence API and hard-gate registry). The Proof* prefix keeps them
// distinct from the VantageStage constants in abd_path.go.
const (
	ProofStageDNS  = "dns"
	ProofStageTCP  = "tcp"
	ProofStageTLS  = "tls"
	ProofStageHTTP = "http"
	ProofStageQUIC = "quic"

	OutcomeProofOK         = "ok"
	OutcomeProofTimeout    = "timeout"
	OutcomeProofRefused    = "refused"
	OutcomeProofBlocked    = "blocked"
	OutcomeProofBad        = "bad"
	OutcomeProofIncomplete = "incomplete"
)

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
