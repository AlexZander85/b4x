package nfq

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/fixtures"
)

func resetSteerStore() {
	steerFlows = &steerSuppressStore{flows: make(map[string]time.Time)}
	steerClients = &steerSuppressStore{flows: make(map[string]time.Time)}
}

func echCHPayload(ech bool, targetSize int) []byte {
	return fixtures.BuildTLSClientHello("rr1---sn-4g5edndd.googlevideo.com", 0x0304, ech, targetSize)
}

func TestSteerDecisionOnlyYouTubeVideoWithECH(t *testing.T) {
	if !steerECHEnabled {
		t.Skip("steer family is compile-time disabled in diagnostic builds")
	}
	resetSteerStore()
	video := &config.SetConfig{Name: "youtube-video", Id: "9b31cb9b-2bdc-4435-bfd6-f7977dca4876"}
	ui := &config.SetConfig{Name: "youtube-ui"}
	api := &config.SetConfig{Name: "combo-timestamp"}

	if !steerDecision(video, echCHPayload(true, 1800)) {
		t.Fatal("youtube-video + ECH must steer")
	}
	if steerDecision(video, echCHPayload(false, 1800)) {
		t.Fatal("youtube-video without ECH must keep fake+combo")
	}
	if steerDecision(ui, echCHPayload(true, 1800)) || steerDecision(api, echCHPayload(true, 1800)) {
		t.Fatal("UI/API must never be steered")
	}
	if steerDecision(nil, echCHPayload(true, 1800)) {
		t.Fatal("nil set must not steer")
	}
}

func TestSteerSuppressStoreTTL(t *testing.T) {
	s := &steerSuppressStore{flows: make(map[string]time.Time)}
	now := time.Now()
	s.suppress("k", now)
	if !s.suppressed("k", now.Add(time.Second)) {
		t.Fatal("fresh entry must be suppressed")
	}
	if s.suppressed("k", now.Add(steerSuppressTTL+time.Second)) {
		t.Fatal("entry must expire after TTL")
	}
}

func steerFixturePacket(t *testing.T, payload []byte) ([]byte, *pktInfo) {
	t.Helper()
	raw := ipv4TCPPacket(1000, payload)
	pkt := &pktInfo{
		raw:    raw,
		ver:    IPv4,
		src:    []byte{192, 168, 1, 152},
		dst:    []byte{173, 194, 6, 6},
		srcStr: "192.168.1.152",
		dstStr: "173.194.6.6",
		srcMac: "22:30:F3:33:62:27",
		ihl:    20,
	}
	return raw, pkt
}

func newSteerTestWorker() *Worker {
	w := &Worker{}
	w.cfg.Store(&config.Config{})
	return w
}

func TestMaybeSteerECHFlowConsumesAndSuppresses(t *testing.T) {
	if !steerECHEnabled {
		t.Skip("steer family is compile-time disabled in diagnostic builds")
	}
	resetSteerStore()
	video := &config.SetConfig{Name: "youtube-video", Id: "9b31cb9b-2bdc-4435-bfd6-f7977dca4876"}
	w := newSteerTestWorker()
	vc := &verdictCtx{verdict: engine.VerdictAccept}

	raw, pkt := steerFixturePacket(t, echCHPayload(true, 1800))
	if !w.maybeSteerECHFlow(vc, pkt, video, raw) {
		t.Fatal("doomed handshake must be steered")
	}
	if vc.verdict != engine.VerdictDrop {
		t.Fatalf("steered packet verdict = %v want drop", vc.verdict)
	}

	// Retransmit of the steered flow is silently dropped too.
	vc2 := &verdictCtx{verdict: engine.VerdictAccept}
	if !w.maybeSteerECHFlow(vc2, pkt, video, raw) {
		t.Fatal("suppressed flow packet must still be consumed")
	}
	if vc2.verdict != engine.VerdictDrop {
		t.Fatalf("suppressed verdict = %v want drop", vc2.verdict)
	}
}

func TestMaybeSteerECHFlowSparesCleanClientHello(t *testing.T) {
	resetSteerStore()
	video := &config.SetConfig{Name: "youtube-video", Id: "9b31cb9b-2bdc-4435-bfd6-f7977dca4876"}
	w := newSteerTestWorker()

	raw, pkt := steerFixturePacket(t, echCHPayload(false, 776))
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	if w.maybeSteerECHFlow(vc, pkt, video, raw) {
		t.Fatal("ECH-free ClientHello must reach the regular inject path")
	}
	if vc.verdict != engine.VerdictAccept {
		t.Fatalf("clean flow verdict changed to %v", vc.verdict)
	}
}

func TestSteerSuppressedDropGatesPacketsBeforeParsing(t *testing.T) {
	if !steerECHEnabled {
		t.Skip("steer family is compile-time disabled in diagnostic builds")
	}
	resetSteerStore()
	payload := echCHPayload(true, 1800)
	raw, pkt := steerFixturePacket(t, payload)
	pi, ok := ExtractPacketInfoV4(raw)
	if !ok {
		t.Fatal("extract")
	}
	sport := binary.BigEndian.Uint16(raw[pi.IPHdrLen : pi.IPHdrLen+2])
	dport := binary.BigEndian.Uint16(raw[pi.IPHdrLen+2 : pi.IPHdrLen+4])

	if steerSuppressedDrop(pkt, sport, dport) {
		t.Fatal("nothing steered yet")
	}
	steerFlows.suppress(steerKey(pkt, sport, dport), time.Now())
	if !steerSuppressedDrop(pkt, sport, dport) {
		t.Fatal("steered flow packets must be gated")
	}
}

// --- L-steer v2: client-scoped SYN suppression ---

func steerVideoSet() *config.SetConfig {
	return &config.SetConfig{Name: "youtube-video", Id: "9b31cb9b-2bdc-4435-bfd6-f7977dca4876"}
}

func TestSteerArmsClientScopeAgainstRetryStorm(t *testing.T) {
	if !steerECHEnabled {
		t.Skip("steer family is compile-time disabled in diagnostic builds")
	}
	resetSteerStore()
	w := newSteerTestWorker()
	vc := &verdictCtx{verdict: engine.VerdictAccept}

	raw, pkt := steerFixturePacket(t, echCHPayload(true, 1800))
	if !w.maybeSteerECHFlow(vc, pkt, steerVideoSet(), raw) {
		t.Fatal("doomed handshake must be steered")
	}

	// Cronet retry: fresh source port, same device, same doomed dstIP.
	// The scope key must ignore ports entirely — that is the v1 lesson.
	retry := *pkt
	retry.srcStr = "192.168.1.152"
	retry.dstStr = "173.194.6.6"
	if !steerClientSYNSuppressedDrop(classifier.TCPFlagSYN, &retry) {
		t.Fatal("fresh-tuple SYN inside armed client scope must be dropped")
	}

	// Data segments are never gated by the client scope.
	if steerClientSYNSuppressedDrop(classifier.TCPFlagACK, &retry) {
		t.Fatal("non-SYN packets must pass the client-scope gate")
	}
	if steerClientSYNSuppressedDrop(classifier.TCPFlagSYN|classifier.TCPFlagACK, &retry) {
		t.Fatal("SYN+ACK must not be treated as a bare SYN")
	}

	// A different destination from the same device is out of scope.
	otherDst := *pkt
	otherDst.dstStr = "142.250.74.36"
	if steerClientSYNSuppressedDrop(classifier.TCPFlagSYN, &otherDst) {
		t.Fatal("SYN toward another dstIP must not be gated")
	}
}

func TestSteerClientScopeExpires(t *testing.T) {
	s := &steerSuppressStore{flows: make(map[string]time.Time)}
	now := time.Now()
	s.suppress("k", now)
	if !s.suppressed("k", now.Add(steerClientTTL-time.Second)) {
		t.Fatal("fresh scope entry must gate")
	}
	if s.suppressed("k", now.Add(steerClientTTL+time.Second)) {
		t.Fatal("client scope must expire after steerClientTTL")
	}
}

func TestCleanHandshakeDoesNotArmClientScope(t *testing.T) {
	resetSteerStore()
	w := newSteerTestWorker()

	raw, pkt := steerFixturePacket(t, echCHPayload(false, 776))
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	if w.maybeSteerECHFlow(vc, pkt, steerVideoSet(), raw) {
		t.Fatal("ECH-free ClientHello must reach the regular inject path")
	}
	if steerClientSYNSuppressedDrop(classifier.TCPFlagSYN, pkt) {
		t.Fatal("clean handshake must not arm the client scope")
	}
}
