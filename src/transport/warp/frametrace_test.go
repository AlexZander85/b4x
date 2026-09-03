package transportwarp

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildIPv4TCP assembles a minimal IPv4+TCP packet for meta-parsing tests.
func buildIPv4TCP(src, dst [4]byte, sport, dport uint16, seq uint32, flags byte, payload int) []byte {
	pkt := make([]byte, 20+20+payload)
	pkt[0] = 0x45 // v4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[13] = flags
	return pkt
}

func TestPktMetaIPv4TCP(t *testing.T) {
	src := [4]byte{100, 64, 0, 2}
	dst := [4]byte{1, 1, 1, 1}
	pkt := buildIPv4TCP(src, dst, 51000, 443, 0xdeadbeef, 0x18 /*PSH|ACK*/, 119)

	l, ok := pktMeta(pkt)
	if !ok {
		t.Fatal("pktMeta rejected a valid IPv4 TCP packet")
	}
	if l.Proto != 6 || l.Src != "100.64.0.2" || l.Dst != "1.1.1.1" {
		t.Fatalf("bad addresses/proto: %+v", l)
	}
	if l.SPort != 51000 || l.DPort != 443 {
		t.Fatalf("bad ports: %+v", l)
	}
	if l.TCPSeq != 0xdeadbeef {
		t.Fatalf("bad seq: %#x", l.TCPSeq)
	}
	if l.TCPFlag != "PSH|ACK" {
		t.Fatalf("bad flag summary %q", l.TCPFlag)
	}
	if l.Head != "" {
		t.Fatalf("parsable packet must not carry head hex, got %q", l.Head)
	}
}

func TestPktMetaRejectsNonIPv4(t *testing.T) {
	if _, ok := pktMeta([]byte{0x60, 0x00, 0x00, 0x00}); ok {
		t.Fatal("IPv6-looking buffer must be reported unparsable")
	}
	if _, ok := pktMeta(nil); ok {
		t.Fatal("empty buffer must be reported unparsable")
	}
}

func TestTraceDisabledByDefault(t *testing.T) {
	t.Setenv(EnvFrameTrace, "")
	if traceEnabled() {
		t.Fatal("trace must be disabled without B4_WARP_FRAMETRACE")
	}
	s := &Session{}
	s.traceTx([]byte{0x45}, 0, nil) // must not panic
}

func TestTraceWritesJSONLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.jsonl")
	t.Setenv(EnvFrameTrace, path)
	initFrameTrace() // re-read the env var into the test process sink

	pkt := buildIPv4TCP([4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8}, 1234, 53, 7, 0x02, 0)
	s := &Session{}
	s.cfg.Endpoint = netip.MustParseAddrPort("162.159.198.2:443")
	s.traceTx(pkt, 3, nil)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("trace file not written: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d", len(lines))
	}
	var l map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &l); err != nil {
		t.Fatalf("line is not JSON: %v", err)
	}
	if l["dir"] != "tx" || l["wr_ms"] != float64(3) || l["dport"] != float64(53) {
		t.Fatalf("unexpected trace content: %v", l)
	}
}

func TestTCPSynFlagNames(t *testing.T) {
	if got := tcpFlagNames(0x02); got != "SYN" {
		t.Fatalf("SYN: %q", got)
	}
	if got := tcpFlagNames(0x12); got != "SYN|ACK" {
		t.Fatalf("SYN|ACK: %q", got)
	}
	if got := tcpFlagNames(0x00); got != "0x00" {
		t.Fatalf("zero flags: %q", got)
	}
}
