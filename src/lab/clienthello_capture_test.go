package lab

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/fixtures"
)

func captureClient(ip string, mac byte) classifier.ClientKey {
	return classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr(ip), SourceMAC: [6]byte{0x02, 0, 0, 0, 0, mac}}
}

func captureRequest(client classifier.ClientKey, retention ProfileRetention) CaptureRequest {
	return CaptureRequest{
		Filter:    ClientFilter{Client: client},
		Duration:  time.Second,
		Retention: retention,
		Source:    "android-nfq-test",
		SourceApp: "youtube-android",
		Interface: "lan0",
		Clock:     clock.NewFixed(time.Unix(1000, 0)),
	}
}

func tcpCaptureFlow(client classifier.ClientKey, destination string, record []byte, cuts ...int) []CaptureSegment {
	dst := netip.MustParseAddr(destination)
	segments := []CaptureSegment{{Client: client, SrcIP: client.SourceIP, DstIP: dst, SrcPort: 42000, DstPort: 443, Sequence: 100, Flags: classifier.TCPFlagSYN}}
	start := 0
	sequence := uint32(101)
	for _, end := range cuts {
		segments = append(segments, CaptureSegment{Client: client, SrcIP: client.SourceIP, DstIP: dst, SrcPort: 42000, DstPort: 443, Sequence: sequence, Flags: classifier.TCPFlagACK, Payload: append([]byte(nil), record[start:end]...)})
		sequence += uint32(end - start)
		start = end
	}
	segments = append(segments, CaptureSegment{Client: client, SrcIP: client.SourceIP, DstIP: dst, SrcPort: 42000, DstPort: 443, Sequence: sequence, Flags: classifier.TCPFlagACK, Payload: append([]byte(nil), record[start:]...)})
	return segments
}

func TestCaptureClientHellosTwoSegmentOutOfOrderRetransmit(t *testing.T) {
	client := captureClient("192.0.2.101", 0x01)
	record := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1800)
	cut := len(record) / 2
	flow := tcpCaptureFlow(client, "203.0.113.101", record, cut)
	// Keep SYN first, then deliver the second half, its identical retransmit,
	// and finally the first half. Production reassembly must recover the stream.
	segments := []CaptureSegment{flow[0], flow[2], flow[2], flow[1]}
	retention := NewMemoryRetention(4)
	result, err := CaptureClientHellos(nil, captureRequest(client, retention), &SliceSource{Segments: segments})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Profiles) != 1 || result.CompletedFlows != 1 || result.DuplicateSegments != 1 {
		t.Fatalf("split/out-of-order/retransmit was not preserved: %+v", result)
	}
	profile := result.Profiles[0]
	if profile.Metadata.SNIHash == "" || profile.Metadata.ClientHelloSize <= 0 || profile.HelloHash == "" || !profile.PrivacySafe {
		t.Fatalf("profile metadata/hash incomplete: %+v", profile)
	}
	if profile.Metadata.SNIHash == "api.youtube.com" {
		t.Fatal("clear SNI leaked into profile")
	}
	if len(retention.List()) != 1 {
		t.Fatalf("retention stored %d profiles", len(retention.List()))
	}
}

func TestCaptureClientHellosMultipleFlowsAndECH(t *testing.T) {
	client := captureClient("192.0.2.102", 0x02)
	record := fixtures.BuildTLSClientHello("outer.example", 0x0304, true, 0)
	flowA := tcpCaptureFlow(client, "203.0.113.102", record, 17)
	flowB := tcpCaptureFlow(client, "203.0.113.103", record, 23)
	// Two simultaneous IPv4 flows must be retained independently.
	request := captureRequest(client, nil)
	result, err := CaptureClientHellos(nil, request, &SliceSource{Segments: append(flowA, flowB...)})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Profiles) != 2 {
		t.Fatalf("multiple simultaneous flows were merged: %+v", result)
	}
	for _, profile := range result.Profiles {
		if !profile.Metadata.ECHPresent || profile.IPFamily != "ipv4" {
			t.Fatalf("ECH/family metadata missing: %+v", profile)
		}
	}
	client6 := classifier.ClientKey{L3Family: 6, SourceIP: netip.MustParseAddr("2001:db8::102"), SourceMAC: [6]byte{0x02, 0, 0, 0, 0, 0x07}}
	ipv6, err := CaptureClientHellos(nil, captureRequest(client6, nil), &SliceSource{Segments: tcpCaptureFlow(client6, "2001:db8::103", record, 23)})
	if err != nil || len(ipv6.Profiles) != 1 || ipv6.Profiles[0].IPFamily != "ipv6" {
		t.Fatalf("IPv6 capture was not supported: %+v err=%v", ipv6, err)
	}
}

func TestCaptureClientHellosIPAndMACFilters(t *testing.T) {
	client := captureClient("192.0.2.107", 0x07)
	record := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	segment := tcpCaptureFlow(client, "203.0.113.107", record)[0:]
	ipRequest := captureRequest(client, nil)
	ipRequest.Filter = ClientFilter{IP: client.SourceIP}
	if result, err := CaptureClientHellos(nil, ipRequest, &SliceSource{Segments: segment}); err != nil || len(result.Profiles) != 1 {
		t.Fatalf("IP-only filter rejected selected client: %+v err=%v", result, err)
	}
	macRequest := captureRequest(client, nil)
	macRequest.Filter = ClientFilter{MAC: client.SourceMAC, HasMAC: true}
	if result, err := CaptureClientHellos(nil, macRequest, &SliceSource{Segments: segment}); err != nil || len(result.Profiles) != 1 {
		t.Fatalf("MAC-only filter rejected selected client: %+v err=%v", result, err)
	}
}

func TestCaptureClientHellosNoTrafficMalformedAndPrivacyExport(t *testing.T) {
	client := captureClient("192.0.2.103", 0x03)
	request := captureRequest(client, nil)
	noTraffic, err := CaptureClientHellos(nil, request, &SliceSource{})
	if err != nil || noTraffic.StopReason != "no-traffic" || len(noTraffic.Profiles) != 0 {
		t.Fatalf("no traffic was not handled safely: %+v err=%v", noTraffic, err)
	}
	malformed := fixtures.BuildTLSClientHello("malformed.example", 0x0304, false, 0)
	malformed[5] = 2 // unexpected first handshake type
	result, err := CaptureClientHellos(nil, request, &SliceSource{Segments: tcpCaptureFlow(client, "203.0.113.103", malformed)})
	if err != nil || len(result.Profiles) != 0 || result.RejectedSegments == 0 {
		t.Fatalf("malformed capture produced a profile: %+v err=%v", result, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "malformed.example") || strings.Contains(string(encoded), "Payload") {
		t.Fatalf("privacy export leaked capture content: %s", encoded)
	}
}

func TestCaptureClientHellosBoundedRequestAndFileRetention(t *testing.T) {
	client := captureClient("192.0.2.104", 0x04)
	request := captureRequest(client, nil)
	request.Duration = 24 * time.Hour
	request.MaxFlows = 99999
	request.MaxProfiles = 99999
	request.MaxBytesPerFlow = 99999
	normalized, err := request.normalized()
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Duration > 5*time.Minute || normalized.MaxFlows > 256 || normalized.MaxProfiles > 256 || normalized.MaxBytesPerFlow > classifier.TLSClientHelloBound() {
		t.Fatalf("capture request exceeded bounds: %+v", normalized)
	}
	tmp := t.TempDir()
	retention := &JSONLRetention{Path: filepath.Join(tmp, "profiles.jsonl"), MaxBytes: 4096}
	record := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	result, err := CaptureClientHellos(nil, captureRequest(client, retention), &SliceSource{Segments: tcpCaptureFlow(client, "203.0.113.104", record)})
	if err != nil || len(result.Profiles) != 1 {
		t.Fatalf("file retention capture failed: %+v err=%v", result, err)
	}
	stat, err := os.Stat(retention.Path)
	if err != nil || stat.Size() > retention.MaxBytes || stat.Mode().Perm() != 0o600 {
		t.Fatalf("retention file was not bounded/private: stat=%+v err=%v", stat, err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "profiles.jsonl")); errors.Is(err, os.ErrNotExist) {
		t.Fatal("retention file was not created")
	}
}

func TestChannelSinkIsBoundedAndCopiesPayload(t *testing.T) {
	channel := make(chan CaptureSegment, 1)
	sink := ChannelSink{Segments: channel, MaxPayload: 8}
	payload := []byte("payload")
	segment := CaptureSegment{Payload: payload}
	if !sink.Submit(segment) {
		t.Fatal("first bounded segment was dropped")
	}
	payload[0] = 'X'
	received := <-channel
	if string(received.Payload) != "payload" {
		t.Fatal("sink retained caller-owned payload")
	}
	if sink.Submit(segment) == false || sink.Submit(segment) {
		t.Fatal("full channel did not fail-open with a nonblocking drop")
	}
}

func FuzzCaptureSegmentValidation(f *testing.F) {
	f.Add(uint16(443), uint32(100), byte(classifier.TCPFlagACK), []byte("small"))
	f.Fuzz(func(t *testing.T, port uint16, sequence uint32, flags byte, payload []byte) {
		client := captureClient("192.0.2.105", 0x05)
		request := captureRequest(client, nil)
		segment := CaptureSegment{Client: client, SrcIP: client.SourceIP, DstIP: netip.MustParseAddr("203.0.113.105"), SrcPort: 42000, DstPort: port, Sequence: sequence, Flags: flags, Payload: payload}
		_ = validateSegment(segment, request.Filter)
	})
}

func BenchmarkCaptureClientHellos(b *testing.B) {
	client := captureClient("192.0.2.106", 0x06)
	record := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1800)
	segments := tcpCaptureFlow(client, "203.0.113.106", record, len(record)/2)
	request := captureRequest(client, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = CaptureClientHellos(nil, request, &SliceSource{Segments: segments})
	}
}
