// Package monitor owns continuous passive observations and temporal control
// decisions. It never imports packet action or config mutation packages.
package monitor

import "time"

const SchemaVersion uint16 = 1

type ClientScopeKey struct {
	ID   string
	Role string // forwarded | router-origin
}

type MonitorScopeKey struct {
	ClientScope       ClientScopeKey
	ServiceProfileID  string
	ComponentID       string
	DomainIdentityID  string
	TargetRole        string // target | control
	DestinationIPHash string
	DestinationPort   uint16
	L4Protocol        uint8
	IPFamily          string
	BindingID         string
	PathMode          string
	NetworkContextID  string
	ConfigGeneration  uint64
}

func (s MonitorScopeKey) Valid() bool {
	if s.ClientScope.Role != "router-origin" && s.ClientScope.ID == "" {
		return false
	}
	if s.ClientScope.Role != "forwarded" && s.ClientScope.Role != "router-origin" {
		return false
	}
	if s.ConfigGeneration == 0 || s.NetworkContextID == "" {
		return false
	}
	if s.TargetRole != "target" && s.TargetRole != "control" {
		return false
	}
	return true
}

type ObservationSource string

const (
	SourceDNSQuery       ObservationSource = "dns_query"
	SourceDNSAnswer      ObservationSource = "dns_answer"
	SourcePacketSNI      ObservationSource = "packet_sni"
	SourceReassembledSNI ObservationSource = "reassembled_sni"
	SourceQUICSNI        ObservationSource = "quic_sni"
	SourceQUICResponse   ObservationSource = "quic_response"
	SourceTCPSYN         ObservationSource = "tcp_syn"
	SourceTCPSYNACK      ObservationSource = "tcp_synack"
	SourceTCPRST         ObservationSource = "tcp_rst"
	SourceTLSAlert       ObservationSource = "tls_alert"
	SourceTLSHello       ObservationSource = "tls_server_hello"
	SourceHTTPHeaders    ObservationSource = "http_headers"
	SourceHTTPProgress   ObservationSource = "http_body_progress"
	SourceUniqueProgress ObservationSource = "unique_inbound_progress"
	SourceSilentStall    ObservationSource = "silent_stall"
	SourceFlowRetry      ObservationSource = "flow_retry"
	SourceQueueDrop      ObservationSource = "queue_drop"
	SourcePPEVisibility  ObservationSource = "ppe_visibility"
	SourceControlSuccess ObservationSource = "control_success"
	SourceControlFailure ObservationSource = "control_failure"
	SourceABDResult      ObservationSource = "abd_result"
	SourceCanaryResult   ObservationSource = "canary_result"
)

type EvidenceAuthority string

const (
	AuthorityPassiveObservation EvidenceAuthority = "passive-observation"
	AuthorityProvisionalFast    EvidenceAuthority = "provisional-fast"
	AuthorityAuthoritativeABD   EvidenceAuthority = "authoritative-abd"
	AuthorityAndroidCanary      EvidenceAuthority = "android-canary"
)

type FailureAttribution string

const (
	AttributionUnknown    FailureAttribution = "unknown"
	AttributionTransport  FailureAttribution = "transport"
	AttributionOrigin     FailureAttribution = "origin"
	AttributionVisibility FailureAttribution = "visibility"
)

type MonitorObservation struct {
	SchemaVersion        uint16
	ObservationID        string
	Scope                MonitorScopeKey
	Source               ObservationSource
	OutcomeCode          string
	FailureAttribution   FailureAttribution
	Authority            EvidenceAuthority
	ObservedAt           time.Time
	ExpiresAt            time.Time
	MonotonicNS          uint64
	ResolutionSnapshotID string
	FlowTraceID          string
	EvidenceRefs         []string
	UniqueBytesIn        uint64
	UniqueBytesOut       uint64
	PacketCountIn        uint64
	PacketCountOut       uint64
	RetryCount           uint16
	SourceHealthID       string
	VisibilitySnapshotID string
}

func (o MonitorObservation) Valid(now time.Time) bool {
	if o.SchemaVersion != SchemaVersion || o.ObservationID == "" || !o.Scope.Valid() || o.Source == "" || o.Authority == "" || o.ObservedAt.IsZero() {
		return false
	}
	return o.ExpiresAt.IsZero() || now.Before(o.ExpiresAt)
}
