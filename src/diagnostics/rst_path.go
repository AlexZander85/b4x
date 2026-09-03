package diagnostics

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/sock"
)

const (
	maxSYNTraceTTL     = 64
	maxSYNTraceSamples = 64
	maxRSTPacketBytes  = 256
	RSTFlag            = 0x04
	RSTACKFlag         = 0x14
)

type RSTTarget uint8

const (
	RSTTargetSource RSTTarget = iota + 1
	RSTTargetDestination
)

type RSTFlowPhase string

const (
	RSTPhaseClientHello    RSTFlowPhase = "clienthello"
	RSTPhaseEstablished    RSTFlowPhase = "established"
	RSTPhaseServerProgress RSTFlowPhase = "server-progress"
)

var (
	ErrRSTNotConfigured = errors.New("controlled RST requires explicit configuration")
	ErrRSTPathInvalid   = errors.New("controlled RST packet path proof is invalid")
	ErrRSTFlowInvalid   = errors.New("controlled RST requires established TCP progress")
	ErrRSTPacketInvalid = errors.New("controlled RST source packet is invalid")
	ErrRSTDisabled      = errors.New("controlled RST kill switch is disabled")
	ErrSYNTraceInvalid  = errors.New("invalid SYN traceroute request")
)

// RSTPathProof is a snapshot of capabilities checked immediately before a
// controlled RST. It intentionally contains no mutable config pointer.
type RSTPathProof struct {
	CaptureEnvelopeValid bool
	ConntrackVisible     bool
	OffloadClear         bool
	RawSendAvailable     bool
	IPv4Supported        bool
	IPv6Supported        bool
}

func (p RSTPathProof) Validate(family capture.AddressFamily) error {
	if !p.CaptureEnvelopeValid || !p.ConntrackVisible || !p.OffloadClear || !p.RawSendAvailable {
		return ErrRSTPathInvalid
	}
	if family == capture.AddressFamilyIPv4 && !p.IPv4Supported {
		return ErrRSTPathInvalid
	}
	if family == capture.AddressFamilyIPv6 && !p.IPv6Supported {
		return ErrRSTPathInvalid
	}
	return nil
}

type ControlledRSTRequest struct {
	Enabled          bool
	StrategyID       string
	ExplicitStrategy bool
	Path             RSTPathProof
	FlowPhase        RSTFlowPhase
	Target           RSTTarget
	OriginalPacket   []byte
	ProcessedMark    uint32
	TTL              uint8
}

type ControlledRSTPlan struct {
	Valid          bool
	Enabled        bool
	StrategyID     string
	Target         RSTTarget
	Family         capture.AddressFamily
	Packet         []byte
	ProcessedMark  uint32
	Sequence       uint32
	Acknowledgment uint32
	TCPFlags       uint8
	Reason         string
}

// PlanControlledRST produces a marked packet intent only after an explicit
// strategy and path proof. It never chooses a strategy from a heuristic hop
// label and never sends a packet itself.
func PlanControlledRST(request ControlledRSTRequest) (ControlledRSTPlan, error) {
	plan := ControlledRSTPlan{Enabled: request.Enabled, StrategyID: request.StrategyID, Target: request.Target, ProcessedMark: request.ProcessedMark}
	if !request.Enabled {
		return plan, ErrRSTDisabled
	}
	if strings.TrimSpace(request.StrategyID) == "" || !request.ExplicitStrategy || request.ProcessedMark == 0 {
		return plan, ErrRSTNotConfigured
	}
	if request.FlowPhase != RSTPhaseEstablished && request.FlowPhase != RSTPhaseServerProgress {
		return plan, ErrRSTFlowInvalid
	}
	if request.Target != RSTTargetSource && request.Target != RSTTargetDestination {
		return plan, ErrRSTNotConfigured
	}
	parsed, err := parseObservedTCP(request.OriginalPacket)
	if err != nil {
		return plan, err
	}
	if err := request.Path.Validate(parsed.family); err != nil {
		return plan, err
	}
	if parsed.flags&capture.TCPFlagSYN != 0 || parsed.flags&capture.TCPFlagRST != 0 || parsed.flags&capture.TCPFlagACK == 0 {
		return plan, ErrRSTFlowInvalid
	}
	ttl := request.TTL
	if ttl == 0 {
		ttl = parsed.ttl
	}
	if ttl == 0 {
		return plan, ErrRSTPacketInvalid
	}
	packet, sequence, acknowledgment, err := buildControlledRST(parsed, request.Target, ttl)
	if err != nil {
		return plan, err
	}
	if len(packet) > maxRSTPacketBytes {
		return plan, ErrRSTPacketInvalid
	}
	plan.Valid = true
	plan.Family = parsed.family
	plan.Packet = packet
	plan.Sequence = sequence
	plan.Acknowledgment = acknowledgment
	plan.TCPFlags = RSTACKFlag
	plan.Reason = "explicit controlled RST path is verified"
	observability.Default().Trace.Record(observability.TraceEvent{Kind: "controlled_rst_planned", Fields: map[string]string{
		"strategy_id": request.StrategyID, "family": fmt.Sprint(parsed.family), "target": fmt.Sprint(request.Target), "heuristic_auto_select": "false",
	}})
	return plan, nil
}

type RSTSender interface {
	Send(packet []byte, processedMark uint32) error
}

type RSTExecutionResult struct {
	Applied  bool
	FailOpen bool
	Bytes    int
	Reason   string
}

func ExecuteControlledRST(plan ControlledRSTPlan, sender RSTSender) RSTExecutionResult {
	result := RSTExecutionResult{}
	if !plan.Valid || plan.ProcessedMark == 0 || len(plan.Packet) == 0 {
		result.FailOpen = true
		result.Reason = "invalid controlled RST plan"
		return result
	}
	if sender == nil {
		result.FailOpen = true
		result.Reason = "raw RST sender unavailable"
		return result
	}
	if err := sender.Send(append([]byte(nil), plan.Packet...), plan.ProcessedMark); err != nil {
		result.FailOpen = true
		result.Reason = "raw RST send failed: " + err.Error()
		return result
	}
	result.Applied = true
	result.Bytes = len(plan.Packet)
	result.Reason = "controlled RST sent with processed mark"
	return result
}

type observedTCP struct {
	packet         []byte
	family         capture.AddressFamily
	ipHeaderLen    int
	tcpOffset      int
	ttl            uint8
	flags          uint8
	sequence       uint32
	acknowledgment uint32
	payloadLen     int
}

func parseObservedTCP(packet []byte) (observedTCP, error) {
	if len(packet) < 20 {
		return observedTCP{}, ErrRSTPacketInvalid
	}
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl+20 || packet[9] != capture.ProtocolTCP {
			return observedTCP{}, ErrRSTPacketInvalid
		}
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if total < ihl+20 || total > len(packet) {
			return observedTCP{}, ErrRSTPacketInvalid
		}
		tcpLen := int(packet[ihl+12]>>4) * 4
		if tcpLen < 20 || ihl+tcpLen > total {
			return observedTCP{}, ErrRSTPacketInvalid
		}
		return observedTCP{packet: packet, family: capture.AddressFamilyIPv4, ipHeaderLen: ihl, tcpOffset: ihl, ttl: packet[8], flags: packet[ihl+13], sequence: binary.BigEndian.Uint32(packet[ihl+4 : ihl+8]), acknowledgment: binary.BigEndian.Uint32(packet[ihl+8 : ihl+12]), payloadLen: total - ihl - tcpLen}, nil
	case 6:
		if len(packet) < 60 || packet[6] != capture.ProtocolTCP {
			return observedTCP{}, ErrRSTPacketInvalid
		}
		payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
		if payloadLength < 20 || 40+payloadLength > len(packet) {
			return observedTCP{}, ErrRSTPacketInvalid
		}
		tcpLen := int(packet[52]>>4) * 4
		if tcpLen < 20 || tcpLen > payloadLength {
			return observedTCP{}, ErrRSTPacketInvalid
		}
		return observedTCP{packet: packet, family: capture.AddressFamilyIPv6, ipHeaderLen: 40, tcpOffset: 40, ttl: packet[7], flags: packet[53], sequence: binary.BigEndian.Uint32(packet[44:48]), acknowledgment: binary.BigEndian.Uint32(packet[48:52]), payloadLen: payloadLength - tcpLen}, nil
	default:
		return observedTCP{}, ErrRSTPacketInvalid
	}
}

func buildControlledRST(source observedTCP, target RSTTarget, ttl uint8) ([]byte, uint32, uint32, error) {
	segmentLength := uint32(source.payloadLen)
	if source.flags&capture.TCPFlagSYN != 0 {
		segmentLength++
	}
	if source.flags&capture.TCPFlagFIN != 0 {
		segmentLength++
	}
	sequence := source.acknowledgment
	acknowledgment := source.sequence + segmentLength
	if source.family == capture.AddressFamilyIPv4 {
		packet := make([]byte, source.ipHeaderLen+20)
		copy(packet, source.packet[:source.ipHeaderLen])
		if target == RSTTargetSource {
			copy(packet[12:16], source.packet[16:20])
			copy(packet[16:20], source.packet[12:16])
		} else {
			copy(packet[12:16], source.packet[12:16])
			copy(packet[16:20], source.packet[16:20])
		}
		packet[8] = ttl
		packet[9] = capture.ProtocolTCP
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[10:12], 0)
		binary.BigEndian.PutUint16(packet[source.ipHeaderLen+0:source.ipHeaderLen+2], binary.BigEndian.Uint16(source.packet[source.tcpOffset+2:source.tcpOffset+4]))
		binary.BigEndian.PutUint16(packet[source.ipHeaderLen+2:source.ipHeaderLen+4], binary.BigEndian.Uint16(source.packet[source.tcpOffset+0:source.tcpOffset+2]))
		binary.BigEndian.PutUint32(packet[source.ipHeaderLen+4:source.ipHeaderLen+8], sequence)
		binary.BigEndian.PutUint32(packet[source.ipHeaderLen+8:source.ipHeaderLen+12], acknowledgment)
		packet[source.ipHeaderLen+12] = 0x50
		packet[source.ipHeaderLen+13] = RSTACKFlag
		binary.BigEndian.PutUint16(packet[source.ipHeaderLen+14:source.ipHeaderLen+16], 0)
		binary.BigEndian.PutUint16(packet[source.ipHeaderLen+16:source.ipHeaderLen+18], 0)
		binary.BigEndian.PutUint16(packet[source.ipHeaderLen+18:source.ipHeaderLen+20], 0)
		sock.FixIPv4Checksum(packet[:source.ipHeaderLen])
		sock.FixTCPChecksum(packet)
		return packet, sequence, acknowledgment, nil
	}
	if source.family == capture.AddressFamilyIPv6 {
		packet := make([]byte, 60)
		copy(packet[:40], source.packet[:40])
		if target == RSTTargetSource {
			copy(packet[8:24], source.packet[24:40])
			copy(packet[24:40], source.packet[8:24])
		}
		packet[6] = capture.ProtocolTCP
		packet[7] = ttl
		binary.BigEndian.PutUint16(packet[4:6], 20)
		binary.BigEndian.PutUint16(packet[40:42], binary.BigEndian.Uint16(source.packet[42:44]))
		binary.BigEndian.PutUint16(packet[42:44], binary.BigEndian.Uint16(source.packet[40:42]))
		binary.BigEndian.PutUint32(packet[44:48], sequence)
		binary.BigEndian.PutUint32(packet[48:52], acknowledgment)
		packet[52] = 0x50
		packet[53] = RSTACKFlag
		binary.BigEndian.PutUint16(packet[54:56], 0)
		binary.BigEndian.PutUint16(packet[56:58], 0)
		binary.BigEndian.PutUint16(packet[58:60], 0)
		sock.FixTCPChecksumV6(packet)
		return packet, sequence, acknowledgment, nil
	}
	return nil, sequence, acknowledgment, ErrRSTPacketInvalid
}

type SYNTracerouteRequest struct {
	Enabled     bool
	Destination netip.Addr
	Port        uint16
	MaxTTL      uint8
	Attempts    uint8
}

type SYNTraceroutePlan struct {
	Valid       bool
	Destination netip.Addr
	Port        uint16
	TTLs        []uint8
	Attempts    uint8
	Reason      string
}

// PlanSYNTraceroute only describes bounded probe TTLs. A transport adapter
// owns socket creation and must keep this diagnostic path separate from the
// production action queue.
func PlanSYNTraceroute(request SYNTracerouteRequest) (SYNTraceroutePlan, error) {
	plan := SYNTraceroutePlan{Destination: request.Destination, Port: request.Port}
	if !request.Enabled || !request.Destination.IsValid() || request.Port == 0 {
		return plan, ErrSYNTraceInvalid
	}
	if request.MaxTTL == 0 {
		request.MaxTTL = 16
	}
	if request.MaxTTL > maxSYNTraceTTL {
		request.MaxTTL = maxSYNTraceTTL
	}
	if request.Attempts == 0 {
		request.Attempts = 1
	}
	if request.Attempts > 3 {
		request.Attempts = 3
	}
	plan.TTLs = make([]uint8, 0, int(request.MaxTTL)*int(request.Attempts))
	for ttl := uint8(1); ttl <= request.MaxTTL; ttl++ {
		for attempt := uint8(0); attempt < request.Attempts; attempt++ {
			plan.TTLs = append(plan.TTLs, ttl)
		}
	}
	plan.Attempts = request.Attempts
	plan.Valid = true
	plan.Reason = "bounded SYN traceroute probe plan"
	return plan, nil
}

type SYNTraceObservation struct {
	TTL        uint8
	Responded  bool
	SourceIP   netip.Addr
	IPID       uint16
	TCPFlags   uint8
	ObservedAt time.Time
	RTT        time.Duration
}

type SYNTracerouteResult struct {
	Observations      []SYNTraceObservation
	FirstResponderTTL uint8
	FirstResponderIP  netip.Addr
	InferredRSTTTL    uint8
	HeuristicOnly     bool
	Reason            string
}

func AnalyzeSYNTraceroute(observations []SYNTraceObservation) SYNTracerouteResult {
	result := SYNTracerouteResult{HeuristicOnly: true, Observations: make([]SYNTraceObservation, 0, maxSYNTraceSamples)}
	copyObservations := append([]SYNTraceObservation(nil), observations...)
	if len(copyObservations) > maxSYNTraceSamples {
		copyObservations = copyObservations[:maxSYNTraceSamples]
	}
	sort.SliceStable(copyObservations, func(i, j int) bool {
		if copyObservations[i].TTL != copyObservations[j].TTL {
			return copyObservations[i].TTL < copyObservations[j].TTL
		}
		return copyObservations[i].ObservedAt.Before(copyObservations[j].ObservedAt)
	})
	for _, observation := range copyObservations {
		if observation.TTL == 0 || !observation.Responded {
			continue
		}
		result.Observations = append(result.Observations, observation)
		if result.FirstResponderTTL == 0 {
			result.FirstResponderTTL = observation.TTL
			result.FirstResponderIP = observation.SourceIP
		}
		if observation.TCPFlags&capture.TCPFlagRST != 0 && result.InferredRSTTTL == 0 {
			result.InferredRSTTTL = observation.TTL
		}
	}
	if result.InferredRSTTTL != 0 {
		result.Reason = "RST responder hop is a heuristic path label"
	} else if result.FirstResponderTTL != 0 {
		result.Reason = "first responding SYN-traceroute hop observed"
	} else {
		result.Reason = "SYN traceroute observed no responding hop"
	}
	return result
}

type RSTPacketObservation struct {
	SourceIP       netip.Addr
	DestinationIP  netip.Addr
	TTL            uint8
	IPID           uint16
	TCPFlags       uint8
	Sequence       uint32
	Acknowledgment uint32
	ObservedAt     time.Time
}

type RSTPathComparison struct {
	Label         string
	Reason        string
	Confidence    uint8
	TTLDelta      int16
	IPIDChanged   bool
	FlagsChanged  bool
	SourceChanged bool
	HeuristicOnly bool
	AutoSelect    bool
}

const (
	RSTLabelNone             = "none"
	RSTLabelPeer             = "peer-rst"
	RSTLabelPossibleInjected = "possible-injected-rst"
	RSTLabelCandidateDelta   = "candidate-path-delta"
	RSTLabelUnknown          = "unknown-rst-path"
)

func CompareRSTPaths(direct, candidate *RSTPacketObservation) RSTPathComparison {
	comparison := RSTPathComparison{Label: RSTLabelUnknown, HeuristicOnly: true, AutoSelect: false}
	if direct == nil && candidate == nil {
		comparison.Label = RSTLabelNone
		comparison.Reason = "no direct or candidate RST observed"
		return comparison
	}
	if direct == nil || candidate == nil {
		comparison.Label = RSTLabelUnknown
		comparison.Confidence = 20
		comparison.Reason = "only one comparison path produced an RST"
		return comparison
	}
	comparison.TTLDelta = int16(direct.TTL) - int16(candidate.TTL)
	comparison.IPIDChanged = direct.IPID != candidate.IPID
	comparison.FlagsChanged = direct.TCPFlags != candidate.TCPFlags
	comparison.SourceChanged = direct.SourceIP != candidate.SourceIP || direct.DestinationIP != candidate.DestinationIP
	if comparison.SourceChanged || absInt16(comparison.TTLDelta) >= 2 || (comparison.IPIDChanged && comparison.FlagsChanged) {
		comparison.Label = RSTLabelCandidateDelta
		comparison.Confidence = 55
		comparison.Reason = "direct and candidate RST metadata differ; path origin is heuristic"
		return comparison
	}
	if direct.SourceIP == candidate.SourceIP && direct.TTL == candidate.TTL && direct.TCPFlags == candidate.TCPFlags {
		comparison.Label = RSTLabelPeer
		comparison.Confidence = 65
		comparison.Reason = "RST metadata is consistent with the peer path"
		return comparison
	}
	comparison.Label = RSTLabelPossibleInjected
	comparison.Confidence = 40
	comparison.Reason = "RST metadata is inconclusive"
	return comparison
}

type RSTPathAnalysis struct {
	Comparison       RSTPathComparison
	Traceroute       SYNTracerouteResult
	HeuristicLabel   string
	Confidence       uint8
	HeuristicOnly    bool
	AutoSelect       bool
	DestructiveReady bool
	Reason           string
}

func AnalyzeRSTPath(traceroute []SYNTraceObservation, direct, candidate *RSTPacketObservation) RSTPathAnalysis {
	trace := AnalyzeSYNTraceroute(traceroute)
	comparison := CompareRSTPaths(direct, candidate)
	label := comparison.Label
	confidence := comparison.Confidence
	if label == RSTLabelNone && trace.InferredRSTTTL != 0 {
		label = RSTLabelPossibleInjected
		confidence = 35
	}
	result := RSTPathAnalysis{
		Comparison: comparison, Traceroute: trace, HeuristicLabel: label, Confidence: confidence,
		HeuristicOnly: true, AutoSelect: false, DestructiveReady: false,
		Reason: "RST path analysis is diagnostic only; inferred hop cannot select a strategy",
	}
	observability.Default().Trace.Record(observability.TraceEvent{Kind: "rst_path_analysis", Fields: map[string]string{
		"label": label, "confidence": fmt.Sprint(confidence), "heuristic_only": "true", "auto_select": "false",
	}})
	return result
}

func absInt16(value int16) int16 {
	if value < 0 {
		return -value
	}
	return value
}
