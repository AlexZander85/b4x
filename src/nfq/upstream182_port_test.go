package nfq

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/quic"
)

// These tests guard the LIVE wiring of the two upstream b4 1.82 strategies —
// udp.mode=coalesce and tcp.http_methodeol — through the real dispatch →
// handleUDPPacket/handleTCPPacket pipeline, so they can never rot into dead
// code: a verdict drop plus a rewritten packet on the wire is asserted, not
// just helper behaviour.

func upstream182TestConfig(t *testing.T, mutate func(*config.SetConfig)) (*config.Config, *config.SetConfig, *Worker, *fakePacketInjector) {
	t.Helper()
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	set := config.NewSetConfig()
	set.Id = "port182"
	set.Name = "port182"
	set.Enabled = true
	set.Targets.IpsToMatch = []string{"203.0.113.10"}
	// Neutralize every default action so the assertion target is exactly the
	// strategy under test.
	set.Fragmentation.Strategy = config.ConfigNone
	set.Fragmentation.StrategyPool = nil
	set.Faking.SNI = false
	set.Faking.SNIMutation.Mode = config.ConfigOff
	set.TCP.Desync.Mode = config.ConfigOff
	set.TCP.Desync.PostDesync = false
	set.TCP.Win.Mode = config.ConfigOff
	set.TCP.DropSACK = false
	set.TCP.SynFake = false
	set.UDP.Mode = config.ConfigOff
	if mutate != nil {
		mutate(&set)
	}
	cfg.Sets = []*config.SetConfig{&set}

	w := NewWorkerWithQueue(&cfg, 0)
	w.matcher.Store(buildMatcher(&cfg))
	// Attach the same runtime state a production pool gives its workers
	// (newPoolWithState), so ProcessPacket exercises the real handler path
	// instead of panicking on nil stores.
	state := newRuntimeState(&cfg)
	w.tlsCache = state.tlsCache
	w.connTracker = state.connState
	w.tcpInjectOnce = state.tcpInjectOnce
	w.chHold = state.chHold
	w.destState = state.destState
	w.quicbound = state.quicbound
	w.echFlow = state.echFlow
	w.scopedFailures = state.scopedFailures
	w.routeBindings = state.routeBindings
	w.fallback = state.fallback
	w.decisions = state.decisions
	w.gsoPassTokens = state.gsoPassTokens
	w.actionTokens = state.actionTokens
	w.passiveRST = state.passiveRST
	w.fastFail = state.fastFail
	w.qbp = state.qbp
	w.ja4 = state.ja4
	fake := &fakePacketInjector{}
	w.strategyInjector = fake
	return &cfg, &set, w, fake
}

// buildQuicLikeInitial assembles a structurally valid QUIC v1 Initial long
// header (real DCID/SCID/token/length/packet-number framing). CoalesceInitial
// only parses the header, so the ciphertext tail is opaque stand-in bytes.
func buildQuicLikeInitial(dcid, scid []byte) []byte {
	pkt := []byte{0xC3, 0x00, 0x00, 0x00, 0x01} // long header, Initial, v1
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	pkt = append(pkt, 0x00) // token length varint = 0
	rest := 4 + 40          // packet number + ciphertext stand-in
	pkt = append(pkt, byte(0x40|(rest>>8)), byte(rest&0xff))
	pkt = binary.BigEndian.AppendUint32(pkt, 0)
	pkt = append(pkt, make([]byte, 40)...)
	return pkt
}

func buildUDPv4Packet(srcIP, dstIP net.IP, sport, dport uint16, payload []byte) []byte {
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	copy(pkt[28:], payload)
	return pkt
}

func TestCoalesceModeIsLiveThroughUDPPipeline(t *testing.T) {
	cfg, _, w, fake := upstream182TestConfig(t, func(set *config.SetConfig) {
		set.UDP.Mode = "coalesce"
	})
	_ = cfg

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	initial := buildQuicLikeInitial(dcid, []byte{1, 2, 3, 4})
	raw := buildUDPv4Packet(net.IPv4(192, 0, 2, 30), net.IPv4(203, 0, 113, 10), 40000, 443, initial)

	verdict := w.ProcessPacket(raw)
	if verdict != engine.VerdictDrop {
		t.Fatalf("coalesce must drop the original datagram for rewrite, got verdict %v", verdict)
	}
	if fake.sent4 != 1 {
		t.Fatalf("coalesce must re-inject exactly one datagram, got %d", fake.sent4)
	}

	sent := fake.last4
	if len(sent) <= len(raw) {
		t.Fatalf("coalesced datagram (%d B) is not larger than the original (%d B)", len(sent), len(raw))
	}
	// UDP header after the 20-byte IPv4 header.
	sentPayload := sent[20+8:]
	if !bytes.HasSuffix(sentPayload, initial) {
		t.Fatal("client Initial is not preserved byte-for-byte at the tail of the datagram")
	}
	gotDCID, _, version, ok := quic.ParseInitialCIDs(sentPayload)
	if !ok {
		t.Fatal("coalesced datagram head is not a parsable Initial")
	}
	if version != 1 {
		t.Fatalf("dummy Initial version %d, want 1", version)
	}
	if !bytes.Equal(gotDCID, dcid) {
		t.Fatalf("dummy Initial header DCID %x, want the client's %x", gotDCID, dcid)
	}
	if _, ok := quic.DecryptInitial(dcid, sentPayload[:len(sentPayload)-len(initial)]); ok {
		t.Fatal("dummy Initial decrypts under the header DCID, the endpoint would process it instead of skipping")
	}
}

func TestCoalesceModeLeavesNonInitialDatagramsAlone(t *testing.T) {
	_, _, w, fake := upstream182TestConfig(t, func(set *config.SetConfig) {
		set.UDP.Mode = "coalesce"
	})

	// Short-header QUIC packet: CoalesceInitial refuses it, the datagram must
	// fail open to accept.
	short := []byte{0x40, 0x01, 0x02, 0x03, 0x04}
	raw := buildUDPv4Packet(net.IPv4(192, 0, 2, 30), net.IPv4(203, 0, 113, 10), 40000, 443, short)

	if verdict := w.ProcessPacket(raw); verdict != engine.VerdictAccept {
		t.Fatalf("non-Initial datagram must be accepted untouched, got verdict %v", verdict)
	}
	if fake.sent4 != 0 {
		t.Fatalf("nothing must be re-injected for a non-Initial datagram, got %d", fake.sent4)
	}
}

func TestHTTPMethodEOLIsLiveThroughTCPPipeline(t *testing.T) {
	_, set, w, fake := upstream182TestConfig(t, func(set *config.SetConfig) {
		set.TCP.HTTPMethodEOL = true
	})
	_ = set

	request := []byte("GET / HTTP/1.1\r\nHost: forum.ru-board.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n")
	pkt := make([]byte, 40+len(request))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 0, 2, 30})
	copy(pkt[16:20], []byte{203, 0, 113, 10})
	binary.BigEndian.PutUint16(pkt[20:22], 50000)
	binary.BigEndian.PutUint16(pkt[22:24], 80)
	pkt[32] = 5 << 4
	copy(pkt[40:], request)

	verdict := w.ProcessPacket(pkt)
	if verdict != engine.VerdictDrop {
		t.Fatalf("http_methodeol must drop the original request for rewrite, got verdict %v", verdict)
	}
	w.wg.Wait()
	if fake.sent4 != 1 {
		t.Fatalf("http_methodeol must re-inject exactly one request, got %d", fake.sent4)
	}

	sent := fake.last4
	if len(sent) != len(pkt) {
		t.Fatalf("rewritten request must keep its exact length (got %d, want %d) or TCP sequence numbers desync", len(sent), len(pkt))
	}
	body := sent[40:]
	if !bytes.HasPrefix(body, []byte("\r\nGET / HTTP/1.1\r\n")) {
		t.Fatalf("request line must be preceded by an empty line: %q", body[:24])
	}
	if !bytes.Contains(body, []byte("Host: forum.ru-board.com")) {
		t.Fatal("Host header was damaged by the rewrite")
	}
	if bytes.Contains(body, []byte("curl/8.5.0")) {
		t.Fatal("User-Agent was not trimmed to pay for the prepended empty line")
	}
	// Fail-safe for the sink itself: the strategy lane must not fire without
	// a usable sender, so a test with strategyInjector nil (production shape
	// before Start()) accepts instead of dropping.
	bare := &Worker{}
	if s := bare.strategySink(); s != nil {
		t.Fatal("strategySink must be nil on an unstarted worker")
	}
}

func TestHTTPMethodEOLOffAcceptsRequestUnchanged(t *testing.T) {
	_, _, w, fake := upstream182TestConfig(t, func(set *config.SetConfig) {
		set.TCP.HTTPMethodEOL = false
	})

	request := []byte("GET / HTTP/1.1\r\nHost: forum.ru-board.com\r\nUser-Agent: curl/8.5.0\r\n\r\n")
	pkt := make([]byte, 40+len(request))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 0, 2, 30})
	copy(pkt[16:20], []byte{203, 0, 113, 10})
	binary.BigEndian.PutUint16(pkt[20:22], 50000)
	binary.BigEndian.PutUint16(pkt[22:24], 80)
	pkt[32] = 5 << 4
	copy(pkt[40:], request)

	if verdict := w.ProcessPacket(pkt); verdict != engine.VerdictAccept {
		t.Fatalf("with http_methodeol off the request must pass unchanged, got verdict %v", verdict)
	}
	w.wg.Wait()
	if fake.sent4 != 0 {
		t.Fatalf("nothing must be re-injected when the option is off, got %d", fake.sent4)
	}
}

func TestHTTPMethodEOLNeedsTCPInjection(t *testing.T) {
	if needsTCPInjection(nil) {
		t.Fatal("nil set must never need injection")
	}
	only := &config.SetConfig{}
	only.TCP.HTTPMethodEOL = true
	if !needsTCPInjection(only) {
		t.Fatal("a set carrying only http_methodeol must be routed into the injection lane, otherwise the option is dead code")
	}
	// A fully neutralized set must stay out of the lane: this is what keeps the
	// option honest — only the explicit flag pulls plain-HTTP traffic in.
	neutral := config.NewSetConfig()
	neutral.Fragmentation.Strategy = config.ConfigNone
	neutral.Fragmentation.StrategyPool = nil
	neutral.Faking.SNI = false
	neutral.Faking.SNIMutation.Mode = config.ConfigOff
	neutral.TCP.Desync.Mode = config.ConfigOff
	neutral.TCP.Desync.PostDesync = false
	neutral.TCP.Win.Mode = config.ConfigOff
	neutral.TCP.DropSACK = false
	neutral.TCP.SynFake = false
	if needsTCPInjection(&neutral) {
		t.Fatal("a neutralized set without http_methodeol must not need injection")
	}
}
