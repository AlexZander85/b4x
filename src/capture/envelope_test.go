package capture

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func testEnvelope(t *testing.T) CaptureEnvelope {
	t.Helper()
	cfg := config.NewConfig()
	cfg.Queue.Threads = 2
	cfg.Queue.StartNum = 537
	cfg.Queue.IPv6Enabled = true
	e, err := NewCaptureEnvelope(&cfg, QueueRoleProduction)
	if err != nil {
		t.Fatal(err)
	}
	e.OutgoingPacketLimit = 2
	e.IncomingPacketLimit = 2
	return e
}

func TestCaptureEnvelopeDecideBoundedDirections(t *testing.T) {
	e := testEnvelope(t)
	for _, tc := range []struct {
		name      string
		direction Direction
		index     uint32
		want      bool
		reason    CaptureReason
	}{
		{name: "first outgoing", direction: DirectionOutgoing, index: 0, want: true, reason: CaptureReasonFirstN},
		{name: "second incoming", direction: DirectionIncoming, index: 1, want: true, reason: CaptureReasonFirstN},
		{name: "outgoing limit", direction: DirectionOutgoing, index: 2, want: false, reason: CaptureReasonNone},
		{name: "incoming limit", direction: DirectionIncoming, index: 2, want: false, reason: CaptureReasonNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Decide(PacketMeta{Family: AddressFamilyIPv4, Direction: tc.direction, Protocol: ProtocolTCP, PacketIndex: tc.index})
			if got.Queue != tc.want || got.Reason != tc.reason {
				t.Fatalf("decision = %+v, want queue=%v reason=%q", got, tc.want, tc.reason)
			}
		})
	}
}

func TestCaptureEnvelopeDecideLifecycleAndQUIC(t *testing.T) {
	e := testEnvelope(t)
	tests := []struct {
		name   string
		meta   PacketMeta
		reason CaptureReason
	}{
		{"syn ack", PacketMeta{Family: AddressFamilyIPv4, Protocol: ProtocolTCP, TCPFlags: TCPFlagSYN | TCPFlagACK}, CaptureReasonSynAck},
		{"fin", PacketMeta{Family: AddressFamilyIPv6, Protocol: ProtocolTCP, TCPFlags: TCPFlagFIN}, CaptureReasonFin},
		{"rst", PacketMeta{Family: AddressFamilyIPv6, Protocol: ProtocolTCP, TCPFlags: TCPFlagRST}, CaptureReasonRst},
		{"quic initial", PacketMeta{Family: AddressFamilyIPv6, Protocol: ProtocolUDP, IsQUICInitial: true}, CaptureReasonQUICInitial},
		{"dns reply", PacketMeta{Family: AddressFamilyIPv4, Protocol: ProtocolUDP, SourcePort: 53}, CaptureReasonDNS},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Decide(tc.meta)
			if !got.Queue || got.Reason != tc.reason {
				t.Fatalf("decision = %+v, want queued as %q", got, tc.reason)
			}
		})
	}
}

func TestCaptureEnvelopeProcessedMarkAndFamilyBypass(t *testing.T) {
	e := testEnvelope(t)
	got := e.Decide(PacketMeta{Family: AddressFamilyIPv4, Protocol: ProtocolTCP, Mark: e.ProcessedMark})
	if got.Queue || got.Reason != CaptureReasonProcessed {
		t.Fatalf("processed packet decision = %+v", got)
	}

	e.IPv6Enabled = false
	got = e.Decide(PacketMeta{Family: AddressFamilyIPv6, Protocol: ProtocolTCP, TCPFlags: TCPFlagFIN})
	if got.Queue || got.Reason != CaptureReasonFamily {
		t.Fatalf("disabled IPv6 decision = %+v", got)
	}
}

func TestCaptureEnvelopeValidation(t *testing.T) {
	e := testEnvelope(t)
	e.QueueThreads = 0
	if err := e.Validate(); err == nil {
		t.Fatal("expected zero queue threads to fail validation")
	}
}

func TestCaptureEnvelopeSeparatesQueueRoles(t *testing.T) {
	cfg := config.NewConfig()
	production, err := NewCaptureEnvelope(&cfg, QueueRoleProduction)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewCaptureEnvelope(&cfg, QueueRoleCandidate)
	if err != nil {
		t.Fatal(err)
	}
	if production.Role == candidate.Role {
		t.Fatalf("queue roles were collapsed: production=%q candidate=%q", production.Role, candidate.Role)
	}
}
