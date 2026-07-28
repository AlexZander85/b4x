package action

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/daniellavrushin/b4/fixtures"
)

func TestDiscoverTLSMarkersAndECHAvailability(t *testing.T) {
	clear := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	markers := DiscoverTLSMarkers(clear)
	if !markers.Complete || markers.Host != "api.youtube.com" || !markers.HostMarkersAvailable() {
		t.Fatalf("clear markers = %+v", markers)
	}
	start, startOK := markers.Find(MarkerHostStart)
	end, endOK := markers.Find(MarkerHostEnd)
	if !startOK || !endOK || string(clear[start.Offset:end.Offset]) != markers.Host {
		t.Fatalf("host marker range start=%+v end=%+v host=%q", start, end, markers.Host)
	}
	if _, ok := markers.Find(MarkerSNIExtensionStart); !ok {
		t.Fatal("SNI extension marker missing")
	}
	if _, ok := markers.Find(MarkerSLDMiddle); !ok {
		t.Fatal("SLD middle marker missing")
	}

	ech := DiscoverTLSMarkers(fixtures.BuildTLSClientHello("", 0x0304, true, 0))
	if !ech.Complete || !ech.ECH || ech.HostMarkersAvailable() {
		t.Fatalf("ECH markers = %+v", ech)
	}
	if _, ok := ech.Find(MarkerHostStart); ok {
		t.Fatal("ECH-only input exposed host marker")
	}
}

func TestStreamMapAndPlanUseLogicalOffsets(t *testing.T) {
	stream := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	mapValue, err := NewStreamMap(0xffffff00, []StreamRange{{Start: 0, Data: stream}})
	if err != nil {
		t.Fatal(err)
	}
	spans, err := mapValue.Spans([]uint64{0, 10, 20})
	if err != nil || len(spans) != 3 || spans[1].Sequence != 0xffffff00+10 {
		t.Fatalf("spans=%+v err=%v", spans, err)
	}
	markers := DiscoverTLSMarkers(fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0))
	payload := bytes.Repeat([]byte{'x'}, 100)
	plan, err := Plan(PlanInput{BaseSequence: 1000, Payload: payload, SplitPositions: []SplitPosition{{Offset: 40, Reason: "test"}}, Markers: markers, MTU: 80, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 0x4000, DryRun: true})
	if err != nil || !plan.Valid || !plan.DryRun || len(plan.Writes) != 3 || plan.Writes[2].Sequence != 1080 || plan.TotalBytes != len(payload) {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if _, err := Plan(PlanInput{BaseSequence: 1, Payload: payload, Markers: markers, MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1, Retransmission: true}); err != ErrRetransmission {
		t.Fatalf("retransmission err=%v", err)
	}
	if _, err := Plan(PlanInput{BaseSequence: 1, Payload: payload, Markers: MarkerSet{ECH: true}, MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1, RequireHostMarkers: true}); err != ErrMarkerUnavailable {
		t.Fatalf("ECH marker requirement err=%v", err)
	}
}

func TestPacketBuilderIPv4AndIPv6PreservesOptionsAndChecksums(t *testing.T) {
	original4 := buildActionIPv4Packet([]byte("original payload"), []byte{1, 1, 1, 1})
	original4Copy := append([]byte(nil), original4...)
	write := PlannedWrite{StreamStart: 5, StreamEnd: 14, Sequence: 7005, Payload: []byte("rewritten")}
	built4, err := (PacketBuilder{MTU: 1500}).Build(original4, write, 0x4000)
	if err != nil || !bytes.Equal(original4, original4Copy) || built4.ProcessedMark != 0x4000 || ValidatePacket(built4.Packet) != nil {
		t.Fatalf("IPv4 build=%+v err=%v validate=%v", built4, err, ValidatePacket(built4.Packet))
	}
	if !bytes.Equal(built4.Packet[40:44], original4[40:44]) || binary.BigEndian.Uint32(built4.Packet[24:24+4]) != write.Sequence {
		t.Fatal("IPv4 TCP options or sequence changed unexpectedly")
	}

	original6 := buildActionIPv6Packet([]byte("original payload"), []byte{1, 1, 1, 1})
	built6, err := (PacketBuilder{MTU: 1500}).Build(original6, PlannedWrite{StreamStart: 0, StreamEnd: 12, Sequence: 8000, Payload: []byte("ipv6 payload")}, 0x4000)
	if err != nil || ValidatePacket(built6.Packet) != nil {
		t.Fatalf("IPv6 build=%+v err=%v validate=%v", built6, err, ValidatePacket(built6.Packet))
	}
	if _, err := (PacketBuilder{MTU: 40}).Build(original4, write, 0x4000); err != ErrMTU {
		t.Fatalf("small MTU err=%v", err)
	}
}

func buildActionIPv4Packet(payload, options []byte) []byte {
	tcpLen := 20 + len(options)
	packet := make([]byte, 20+tcpLen+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], net.IPv4(192, 0, 2, 100).To4())
	copy(packet[16:20], net.IPv4(203, 0, 113, 100).To4())
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 7000)
	tcp[12] = byte(tcpLen / 4 << 4)
	tcp[13] = 0x18
	copy(tcp[20:20+len(options)], options)
	copy(tcp[tcpLen:], payload)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	_ = fixTCPChecksum(packet, 4, 20)
	return packet
}

func buildActionIPv6Packet(payload, options []byte) []byte {
	tcpLen := 20 + len(options)
	packet := make([]byte, 40+tcpLen+len(payload))
	packet[0] = 0x60
	packet[6] = 6
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	copy(packet[8:24], net.ParseIP("2001:db8::100").To16())
	copy(packet[24:40], net.ParseIP("2001:db8::200").To16())
	tcp := packet[40:]
	binary.BigEndian.PutUint16(tcp[0:2], 51001)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 8000)
	tcp[12] = byte(tcpLen / 4 << 4)
	tcp[13] = 0x18
	copy(tcp[20:20+len(options)], options)
	copy(tcp[tcpLen:], payload)
	_ = fixTCPChecksum(packet, 6, 40)
	return packet
}

func FuzzDiscoverTLSMarkersNeverPanics(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x03, 0, 4, 1, 0, 0, 0})
	f.Add(fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0))
	f.Fuzz(func(t *testing.T, payload []byte) {
		markers := DiscoverTLSMarkers(payload)
		_, _ = markers.Find(MarkerHostStart)
		_ = markers.HostMarkersAvailable()
	})
}

func FuzzPlanNeverPanics(f *testing.F) {
	f.Add([]byte("hello"), uint64(2), uint32(1000))
	f.Fuzz(func(t *testing.T, payload []byte, split uint64, base uint32) {
		if len(payload) == 0 {
			payload = []byte("x")
		}
		if split == 0 || split >= uint64(len(payload)) {
			split = uint64(len(payload) / 2)
		}
		_, _ = Plan(PlanInput{BaseSequence: base, Payload: payload, SplitPositions: []SplitPosition{{Offset: split}}, MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1, MaxWrites: 16, MaxBytes: 4096})
	})
}

func BenchmarkDiscoverTLSMarkers(b *testing.B) {
	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1800)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DiscoverTLSMarkers(payload)
	}
}
