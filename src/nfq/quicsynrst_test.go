package nfq

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/sock"
)

func resetQuicSynRstStore() {
	steerClients = &steerSuppressStore{flows: make(map[string]time.Time)}
}

func TestBuildSynRefusedRSTGeometry(t *testing.T) {
	raw, _ := steerFixturePacket(t, echCHPayload(true, 300))
	pi, ok := ExtractPacketInfoV4(raw)
	if !ok {
		t.Fatal("extract")
	}
	clientSeq := binary.BigEndian.Uint32(raw[pi.IPHdrLen+4 : pi.IPHdrLen+8])

	rst := buildSynRefusedRSTv4(raw)
	if rst == nil {
		t.Fatal("builder returned nil")
	}
	sport := binary.BigEndian.Uint16(rst[20:22])
	dport := binary.BigEndian.Uint16(rst[22:24])
	wantSport := binary.BigEndian.Uint16(raw[pi.IPHdrLen+2 : pi.IPHdrLen+4])
	wantDport := binary.BigEndian.Uint16(raw[pi.IPHdrLen : pi.IPHdrLen+2])
	if sport != wantSport || dport != wantDport {
		t.Fatalf("ports %d->%d, want %d->%d", sport, dport, wantSport, wantDport)
	}
	if flags := rst[33]; flags != 0x14 {
		t.Fatalf("flags %#x, want RST|ACK (0x14)", flags)
	}
	if ack := binary.BigEndian.Uint32(rst[28:32]); ack != clientSeq+1 {
		t.Fatalf("ack %d, want ISN+1=%d", ack, clientSeq+1)
	}
	re := append([]byte(nil), rst[:20]...)
	sock.FixIPv4Checksum(re) // idempotent when the checksum is correct
	for i := 0; i < 20; i++ {
		if re[i] != rst[i] {
			t.Fatalf("IPv4 header checksum invalid at byte %d", i)
			break
		}
	}
}

func TestQuicSynRstArmsAndRefuses(t *testing.T) {
	resetQuicSynRstStore()
	w := newSteerTestWorker()

	raw, pkt := steerFixturePacket(t, echCHPayload(true, 1802))

	// Arming requires a classified doomed flow (youtube-video + ECH).
	w.maybeArmQuicSynRst(pkt, steerVideoSet(), raw)
	if !steerClients.suppressed(steerClientKey(pkt), time.Now()) {
		t.Fatal("pair must be armed after doomed classification")
	}
	otherDst := *pkt
	otherDst.dstStr = "142.250.74.36"
	if steerClients.suppressed(steerClientKey(&otherDst), time.Now()) {
		t.Fatal("arming must be scoped to the doomed dstIP")
	}

	// A bare SYN of the armed pair is refused (decision), consumed+dropped.
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	bareSYN := *pkt
	bareSYN.raw = ipv4TCPPacket(1000, nil)
	if !quicSynRstShouldRefuse(&bareSYN, 0x02) {
		t.Fatal("armed bare SYN must be refused")
	}
	if got := w.quicSynRstOnSyn(vc, &bareSYN, 0x02); got != quicSynRstEnabled {
		t.Fatalf("consumed=%v, want %v (compile-time gate; nil sender falls back to regular path)", got, quicSynRstEnabled)
	}
	// Decision-only assertions stay valid regardless of the sender presence.
	if quicSynRstEnabled && quicSynRstShouldRefuse(&bareSYN, 0x10) {
		t.Fatal("ACK packet must not be refused")
	}
	if quicSynRstEnabled && quicSynRstShouldRefuse(&otherDst, 0x02) {
		t.Fatal("SYN toward another dstIP must not be refused")
	}
}

func TestQuicSynRstArmingNeedsECH(t *testing.T) {
	resetQuicSynRstStore()
	w := newSteerTestWorker()
	rawClean, pktClean := steerFixturePacket(t, echCHPayload(false, 776))
	w.maybeArmQuicSynRst(pktClean, steerVideoSet(), rawClean)
	if steerClients.suppressed(steerClientKey(pktClean), time.Now()) {
		t.Fatal("ECH-free flow must not arm the scope")
	}
}

func TestQuicSynRstReArmExtendsWindow(t *testing.T) {
	resetQuicSynRstStore()
	now := time.Now()
	steerClients.suppress("c:mac|d:9.9.9.9", now)
	steerClients.suppress("c:mac|d:9.9.9.9", now.Add(5*time.Second))
	if !steerClients.suppressed("c:mac|d:9.9.9.9", now.Add(14*time.Second)) {
		t.Fatal("re-arm must extend the window")
	}
	if steerClients.suppressed("c:mac|d:9.9.9.9", now.Add(16*time.Second)) {
		t.Fatal("window must expire after TTL from the last arm")
	}
}

func TestQuicboundNoteRefusedCounters(t *testing.T) {
	s := newQuicboundStore()
	s.noteRefused("8.8.8.8", "aa")
	s.noteRefused("8.8.8.8", "aa")
	s.noteRefused("8.8.8.8", "bb")
	if s.refusedTotal != 3 || s.refusedSinceSummary != 3 {
		t.Fatalf("counters %d/%d", s.refusedTotal, s.refusedSinceSummary)
	}
	if got := s.maxRefusedPerPairLocked(); got != 2 {
		t.Fatalf("max per pair %d, want 2", got)
	}
}

func TestQuicSynRstNoopWhenDisabled(t *testing.T) {
	if quicSynRstEnabled {
		t.Skip("enabled in quicsynrst builds")
	}
	resetQuicSynRstStore()
	w := newSteerTestWorker()
	raw, pkt := steerFixturePacket(t, echCHPayload(true, 1802))
	w.maybeArmQuicSynRst(pkt, steerVideoSet(), raw)
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	if w.quicSynRstOnSyn(vc, pkt, 0x02) {
		t.Fatal("disabled build must not consume packets")
	}
}
