package ppe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const SelfTestProtocol = "b4-ppe-self-test/v1"

type SelfTestVerdict string

const (
	VerdictPASS                SelfTestVerdict = "PASS"
	VerdictPASSWithLimitations SelfTestVerdict = "PASS_WITH_LIMITATIONS"
	VerdictFAIL                SelfTestVerdict = "FAIL"
	VerdictUNSUPPORTED         SelfTestVerdict = "UNSUPPORTED"
	VerdictINCONCLUSIVE        SelfTestVerdict = "INCONCLUSIVE"
)

type SelfTestPhase string

const (
	PhaseWithoutExclusion SelfTestPhase = "without_exclusion"
	PhaseWithExclusion    SelfTestPhase = "with_exclusion"
)

type SelfTestRequest struct {
	RunID              string        `json:"run_id"`
	Generation         string        `json:"generation"`
	ControlledEndpoint string        `json:"controlled_endpoint"`
	Family             string        `json:"family"`
	TCPFlowID          string        `json:"tcp_flow_id"`
	QUICFlowID         string        `json:"quic_flow_id,omitempty"`
	TCPSourcePort      uint16        `json:"tcp_source_port"`
	QUICSourcePort     uint16        `json:"quic_source_port,omitempty"`
	RequireQUIC        bool          `json:"require_quic"`
	Timeout            time.Duration `json:"timeout"`
}

func (r SelfTestRequest) Validate() error {
	if strings.TrimSpace(r.RunID) == "" || strings.TrimSpace(r.Generation) == "" {
		return errors.New("run_id and generation are required")
	}
	if strings.TrimSpace(r.ControlledEndpoint) == "" || strings.TrimSpace(r.TCPFlowID) == "" {
		return errors.New("controlled_endpoint and tcp_flow_id are required")
	}
	if r.Family != "ipv4" && r.Family != "ipv6" {
		return fmt.Errorf("unsupported family %q", r.Family)
	}
	if r.TCPSourcePort == 0 {
		return errors.New("tcp_source_port is required")
	}
	if r.RequireQUIC && (r.QUICSourcePort == 0 || strings.TrimSpace(r.QUICFlowID) == "") {
		return errors.New("required QUIC probe needs quic_source_port and quic_flow_id")
	}
	if r.Timeout <= 0 || r.Timeout > 30*time.Second {
		return errors.New("timeout must be greater than zero and at most 30s")
	}
	return nil
}

type ProbeRequest struct {
	RunID              string        `json:"run_id"`
	Phase              SelfTestPhase `json:"phase"`
	Protocol           string        `json:"protocol"`
	Family             string        `json:"family"`
	FlowID             string        `json:"flow_id"`
	SourcePort         uint16        `json:"source_port"`
	ControlledEndpoint string        `json:"controlled_endpoint"`
	Timeout            time.Duration `json:"timeout"`
}

type ProbeOutcome struct {
	Protocol      string `json:"protocol"`
	ClientEmitted bool   `json:"client_emitted"`
	Detail        string `json:"detail,omitempty"`
}

type PhaseEvidence struct {
	Phase                    SelfTestPhase `json:"phase"`
	TCPFirstPayloadSeen      bool          `json:"tcp_first_payload_seen"`
	TCPSecondRangeSeen       bool          `json:"tcp_second_range_seen"`
	TCPRetransmissionSeen    bool          `json:"tcp_retransmission_seen"`
	TCPIncomingProgressSeen  bool          `json:"tcp_incoming_progress_seen"`
	QUICInitialSeen          bool          `json:"quic_initial_seen"`
	QUICIncomingResponseSeen bool          `json:"quic_incoming_response_seen"`
	TCPClientEmitted         bool          `json:"tcp_client_emitted"`
	QUICClientEmitted        bool          `json:"quic_client_emitted"`
}

func (e PhaseEvidence) TCPComplete() bool {
	return e.TCPFirstPayloadSeen && e.TCPSecondRangeSeen && e.TCPRetransmissionSeen && e.TCPIncomingProgressSeen
}

func (e PhaseEvidence) QUICComplete(required bool) bool {
	return !required || (e.QUICInitialSeen && e.QUICIncomingResponseSeen)
}

type CaptureVisibilityResult struct {
	RunID string `json:"run_id"`

	Capability CapabilityState `json:"capability"`
	Policy     string          `json:"policy"`

	IPv4Active bool `json:"ipv4_active"`
	IPv6Active bool `json:"ipv6_active"`
	TCPActive  bool `json:"tcp_active"`
	QUICActive bool `json:"quic_active"`

	OutgoingFirstPayloadSeen bool `json:"outgoing_first_payload_seen"`
	OutgoingSecondRangeSeen  bool `json:"outgoing_second_range_seen"`
	OutgoingRetransSeen      bool `json:"outgoing_retrans_seen"`
	IncomingProgressSeen     bool `json:"incoming_progress_seen"`

	TCPBidirectionalComplete  bool `json:"tcp_bidirectional_complete"`
	QUICBidirectionalComplete bool `json:"quic_bidirectional_complete"`

	RuleCountersBefore map[string]uint64 `json:"rule_counters_before,omitempty"`
	RuleCountersAfter  map[string]uint64 `json:"rule_counters_after,omitempty"`

	OffloadSuspected bool            `json:"offload_suspected"`
	FailureStage     string          `json:"failure_stage,omitempty"`
	Evidence         []string        `json:"evidence,omitempty"`
	Verdict          SelfTestVerdict `json:"verdict"`
	ProductionReady  bool            `json:"production_ready"`
	StartedAt        time.Time       `json:"started_at"`
	CompletedAt      time.Time       `json:"completed_at"`
	PhaseA           PhaseEvidence   `json:"phase_a"`
	PhaseB           PhaseEvidence   `json:"phase_b"`
}

type HealthChecker interface {
	Check(context.Context, string) error
}

type ProbeExecutor interface {
	Run(context.Context, ProbeRequest) (ProbeOutcome, error)
}

type ABIsolation interface {
	BeginBypass(context.Context, string, string, uint16, uint16) (func(context.Context) error, error)
	VerifyActive(context.Context, string) error
}

type RuleCounterSource interface {
	RuleCounters(context.Context) (map[string]uint64, error)
}

type SelfTestResultStore interface {
	Put(CaptureVisibilityResult)
	Get(string) (CaptureVisibilityResult, bool)
}
