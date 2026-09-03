package diagnostics

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/sock"
)

type rstTestSender struct {
	packet []byte
	mark   uint32
	err    error
}

func (s *rstTestSender) Send(packet []byte, mark uint32) error {
	s.packet = append([]byte(nil), packet...)
	s.mark = mark
	return s.err
}

func rstProof() RSTPathProof {
	return RSTPathProof{CaptureEnvelopeValid: true, ConntrackVisible: true, OffloadClear: true, RawSendAvailable: true, IPv4Supported: true, IPv6Supported: true}
}

func ipv4TCPPacket(flags uint8) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 42)
	packet[8] = 64
	packet[9] = capture.ProtocolTCP
	copy(packet[12:16], netip.MustParseAddr("192.0.2.10").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("203.0.113.10").AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], 41000)
	binary.BigEndian.PutUint16(packet[22:24], 443)
	binary.BigEndian.PutUint32(packet[24:28], 1000)
	binary.BigEndian.PutUint32(packet[28:32], 2000)
	packet[32] = 0x50
	packet[33] = flags
	binary.BigEndian.PutUint16(packet[34:36], 65535)
	sock.FixIPv4Checksum(packet[:20])
	sock.FixTCPChecksum(packet)
	return packet
}

func ipv6TCPPacket(flags uint8) []byte {
	packet := make([]byte, 60)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 20)
	packet[6] = capture.ProtocolTCP
	packet[7] = 64
	copy(packet[8:24], netip.MustParseAddr("2001:db8::10").AsSlice())
	copy(packet[24:40], netip.MustParseAddr("2001:db8::20").AsSlice())
	binary.BigEndian.PutUint16(packet[40:42], 41000)
	binary.BigEndian.PutUint16(packet[42:44], 443)
	binary.BigEndian.PutUint32(packet[44:48], 1000)
	binary.BigEndian.PutUint32(packet[48:52], 2000)
	packet[52] = 0x50
	packet[53] = flags
	sock.FixTCPChecksumV6(packet)
	return packet
}

func TestPlanControlledRSTRequiresExplicitVerifiedPath(t *testing.T) {
	request := ControlledRSTRequest{
		Enabled: true, StrategyID: "rst-diagnostic", ExplicitStrategy: true, Path: rstProof(),
		FlowPhase: RSTPhaseServerProgress, Target: RSTTargetSource, OriginalPacket: ipv4TCPPacket(capture.TCPFlagACK | 0x08), ProcessedMark: 1 << 30, TTL: 52,
	}
	plan, err := PlanControlledRST(request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Valid || plan.Family != capture.AddressFamilyIPv4 || plan.ProcessedMark == 0 || len(plan.Packet) != 40 || plan.TCPFlags != RSTACKFlag {
		t.Fatalf("plan=%+v", plan)
	}
	parsed, err := parseObservedTCP(plan.Packet)
	if err != nil || parsed.flags != RSTACKFlag || parsed.ttl != 52 || parsed.acknowledgment != 1000 {
		t.Fatalf("RST packet=%+v err=%v", parsed, err)
	}
	if got := binary.BigEndian.Uint16(plan.Packet[20:22]); got != 443 {
		t.Fatalf("reply source port=%d, want 443", got)
	}

	sender := &rstTestSender{}
	result := ExecuteControlledRST(plan, sender)
	if !result.Applied || result.FailOpen || sender.mark != request.ProcessedMark || len(sender.packet) != len(plan.Packet) {
		t.Fatalf("execution=%+v sender=%+v", result, sender)
	}
	request.ExplicitStrategy = false
	if _, err := PlanControlledRST(request); !errors.Is(err, ErrRSTNotConfigured) {
		t.Fatalf("implicit strategy error=%v", err)
	}
	request = ControlledRSTRequest{Enabled: true, StrategyID: "rst", ExplicitStrategy: true, Path: rstProof(), FlowPhase: RSTPhaseClientHello, Target: RSTTargetSource, OriginalPacket: ipv4TCPPacket(capture.TCPFlagACK), ProcessedMark: 1}
	if _, err := PlanControlledRST(request); !errors.Is(err, ErrRSTFlowInvalid) {
		t.Fatalf("ClientHello flow error=%v", err)
	}
	request = ControlledRSTRequest{Enabled: true, StrategyID: "rst", ExplicitStrategy: true, Path: RSTPathProof{}, FlowPhase: RSTPhaseEstablished, Target: RSTTargetSource, OriginalPacket: ipv4TCPPacket(capture.TCPFlagACK), ProcessedMark: 1}
	if _, err := PlanControlledRST(request); !errors.Is(err, ErrRSTPathInvalid) {
		t.Fatalf("unverified path error=%v", err)
	}
}

func TestPlanControlledRSTIPv6AndFailOpen(t *testing.T) {
	request := ControlledRSTRequest{Enabled: true, StrategyID: "rst-v6", ExplicitStrategy: true, Path: rstProof(), FlowPhase: RSTPhaseEstablished, Target: RSTTargetDestination, OriginalPacket: ipv6TCPPacket(capture.TCPFlagACK), ProcessedMark: 9}
	plan, err := PlanControlledRST(request)
	if err != nil || !plan.Valid || plan.Family != capture.AddressFamilyIPv6 || len(plan.Packet) != 60 {
		t.Fatalf("IPv6 plan=%+v err=%v", plan, err)
	}
	sender := &rstTestSender{err: errors.New("send failed")}
	result := ExecuteControlledRST(plan, sender)
	if !result.FailOpen || result.Applied {
		t.Fatalf("failed send was not fail-open: %+v", result)
	}
	request.Enabled = false
	if _, err := PlanControlledRST(request); !errors.Is(err, ErrRSTDisabled) {
		t.Fatalf("disabled RST error=%v", err)
	}
	request = ControlledRSTRequest{Enabled: true, StrategyID: "rst", ExplicitStrategy: true, Path: rstProof(), FlowPhase: RSTPhaseEstablished, Target: RSTTargetSource, OriginalPacket: ipv4TCPPacket(capture.TCPFlagSYN), ProcessedMark: 1}
	if _, err := PlanControlledRST(request); !errors.Is(err, ErrRSTFlowInvalid) {
		t.Fatalf("SYN mutation error=%v", err)
	}
}

func TestSYNTracerouteAndRSTPathAnalysisAreHeuristicOnly(t *testing.T) {
	plan, err := PlanSYNTraceroute(SYNTracerouteRequest{Enabled: true, Destination: netip.MustParseAddr("203.0.113.10"), Port: 443, MaxTTL: 70, Attempts: 4})
	if err != nil || !plan.Valid || len(plan.TTLs) != 64*3 {
		t.Fatalf("traceroute plan=%+v err=%v", plan, err)
	}
	now := time.Unix(100, 0)
	trace := AnalyzeSYNTraceroute([]SYNTraceObservation{
		{TTL: 3, Responded: true, SourceIP: netip.MustParseAddr("192.0.2.3"), ObservedAt: now, TCPFlags: capture.TCPFlagRST},
		{TTL: 1, Responded: false, ObservedAt: now.Add(time.Second)},
	})
	if trace.FirstResponderTTL != 3 || trace.InferredRSTTTL != 3 || !trace.HeuristicOnly {
		t.Fatalf("trace=%+v", trace)
	}
	direct := &RSTPacketObservation{SourceIP: netip.MustParseAddr("203.0.113.10"), DestinationIP: netip.MustParseAddr("192.0.2.10"), TTL: 48, IPID: 1, TCPFlags: RSTACKFlag}
	candidate := &RSTPacketObservation{SourceIP: netip.MustParseAddr("192.0.2.1"), DestinationIP: netip.MustParseAddr("192.0.2.10"), TTL: 42, IPID: 2, TCPFlags: RSTFlag}
	comparison := CompareRSTPaths(direct, candidate)
	if comparison.Label != RSTLabelCandidateDelta || comparison.Confidence >= 85 || comparison.AutoSelect {
		t.Fatalf("comparison=%+v", comparison)
	}
	analysis := AnalyzeRSTPath(nil, direct, candidate)
	if !analysis.HeuristicOnly || analysis.AutoSelect || analysis.DestructiveReady || analysis.HeuristicLabel != RSTLabelCandidateDelta {
		t.Fatalf("analysis=%+v", analysis)
	}
	if _, err := PlanSYNTraceroute(SYNTracerouteRequest{Enabled: true, Destination: netip.MustParseAddr("203.0.113.10")}); !errors.Is(err, ErrSYNTraceInvalid) {
		t.Fatalf("missing port error=%v", err)
	}
}

func FuzzPlanControlledRSTNoPanic(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6}, uint8(52), true)
	f.Add([]byte{1, 2, 3}, uint8(0), false)
	f.Fuzz(func(t *testing.T, packet []byte, ttl uint8, enabled bool) {
		_, _ = PlanControlledRST(ControlledRSTRequest{Enabled: enabled, StrategyID: "fuzz-rst", ExplicitStrategy: true, Path: rstProof(), FlowPhase: RSTPhaseEstablished, Target: RSTTargetSource, OriginalPacket: packet, ProcessedMark: 1, TTL: ttl})
	})
}

func BenchmarkPlanControlledRST(b *testing.B) {
	request := ControlledRSTRequest{Enabled: true, StrategyID: "rst-bench", ExplicitStrategy: true, Path: rstProof(), FlowPhase: RSTPhaseEstablished, Target: RSTTargetSource, OriginalPacket: ipv4TCPPacket(capture.TCPFlagACK), ProcessedMark: 1}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = PlanControlledRST(request)
	}
}
