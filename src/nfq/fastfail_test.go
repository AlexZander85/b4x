// b4x-693 fast-fail verification: set eligibility, the stall predicate,
// the per-dstIP budget, and an end-to-end forged-RST run through the BLK-6
// clientInjector seam (one RST per connKey, seq == client's current ACK).
package nfq

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

func ffVideoSet() *config.SetConfig {
	return &config.SetConfig{Name: "youtube-video", Id: "9b31cb9b-2bdc-4435-bfd6-f7977dca4876"}
}

func ffAPISet() *config.SetConfig {
	return &config.SetConfig{Name: "combo-timestamp", Id: "211bf07f-6c56-42be-97ac-151f18face49"}
}

func TestFastFailSetEligible(t *testing.T) {
	if !fastFailSetEligible(ffVideoSet()) || !fastFailSetEligible(ffAPISet()) {
		t.Fatal("youtube-video and combo-timestamp must be eligible")
	}
	for _, s := range []*config.SetConfig{
		nil,
		{Name: "youtube-ui"},
		{Name: "GEO_DNS"},
		{Name: "instagram"},
		{Id: "b6e44188-12f4-460e-9cad-56d3729aa200"}, // youtube-ui by id
	} {
		if fastFailSetEligible(s) {
			t.Fatalf("set %+v must not be eligible", s)
		}
	}
}

func TestFastFailStallPredicate(t *testing.T) {
	now := time.Now()
	f := &fastFailFlow{armedAt: now.Add(-time.Second), lastAdvance: now}

	if fastFailStalled(f, now) {
		t.Fatal("no server ack seen yet: must not fire (pre-handshake guard)")
	}
	f.srvAckSeen = true
	f.srvAck = 133
	f.lastAdvance = now
	if fastFailStalled(f, now) {
		t.Fatal("below byte threshold must not fire")
	}
	f.bytesUnacked = fastFailBytesMin
	if fastFailStalled(f, now.Add(fastFailStallT/2)) {
		t.Fatal("server still advancing: must not fire")
	}
	if !fastFailStalled(f, now.Add(fastFailStallT)) {
		t.Fatal("frozen ack + investment + post-handshake must fire")
	}
	f.rstSent = true
	if fastFailStalled(f, now.Add(10*fastFailStallT)) {
		t.Fatal("one RST per flow: second stall must never re-fire")
	}
	// Ack moving forward resets the clock (wrap-safe comparison included).
	f.rstSent = false
	f.lastAdvance = now
	if fastFailStalled(f, now.Add(fastFailStallT-time.Millisecond)) {
		t.Fatal("fresh progress within T must not fire")
	}
}

func TestFastFailBudgetAllow(t *testing.T) {
	s := newFastFailStore()
	now := time.Now()
	dst := "203.0.113.10"
	for i := 0; i < fastFailRSTBudgetPerDst; i++ {
		if !s.budgetAllow(dst, now) {
			t.Fatalf("rst %d/%d within window must be allowed", i+1, fastFailRSTBudgetPerDst)
		}
	}
	if s.budgetAllow(dst, now.Add(fastFailBudgetWindow/2)) {
		t.Fatal("budget exhaustion must block further RSTs in the window")
	}
	if !s.budgetAllow(dst, now.Add(fastFailBudgetWindow+time.Millisecond)) {
		t.Fatal("new window must restore the budget")
	}
	// Independent per-dstIP scopes.
	if !s.budgetAllow("203.0.113.11", now.Add(fastFailBudgetWindow/2)) {
		t.Fatal("other dstIP must have its own budget")
	}
}

func ffSyntheticOutbound(t *testing.T, sport uint16, payload []byte, flags byte) *pktInfo {
	t.Helper()
	raw := make([]byte, 40+len(payload))
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[8] = 64
	raw[9] = 6
	copy(raw[12:16], net.IPv4(192, 0, 2, 33).To4())   // client
	copy(raw[16:20], net.IPv4(203, 0, 113, 10).To4()) // server (GGC)
	binary.BigEndian.PutUint16(raw[20:22], sport)
	binary.BigEndian.PutUint16(raw[22:24], 443)
	const clientAck = 0x000000aa
	binary.BigEndian.PutUint32(raw[28:32], clientAck)
	raw[32] = 0x50
	raw[33] = flags
	if len(payload) > 0 {
		copy(raw[40:], payload)
	}
	return &pktInfo{
		raw: raw, ver: IPv4, proto: 6,
		src: net.IPv4(192, 0, 2, 33), dst: net.IPv4(203, 0, 113, 10),
		srcStr: "192.0.2.33", dstStr: "203.0.113.10",
		srcMac: "22:30:f3:33:62:27", ihl: 20,
	}
}

func TestFastFailEndToEndForgedRST(t *testing.T) {
	if !fastFailEnabled {
		t.Skip("fast-fail layer is compile-time disabled without -tags fastfail")
	}
	t.Setenv("B4_FASTFAIL_LIVE", "1")
	fastFailLiveOnce = sync.Once{}
	fastFailLiveVal.Store(false)

	w := &Worker{}
	store := newFastFailStore()
	w.fastFail = store
	fake := &fakePacketInjector{}
	w.clientInjector = fake

	pkt := ffSyntheticOutbound(t, 51000, nil, 0x18 /*PSH|ACK*/)

	// Arm via masking funnel.
	w.fastFailArm(pkt, ffVideoSet())
	key := fastFailConnKey(pkt)
	if len(store.flows) != 1 {
		t.Fatalf("arm: store size %d want 1", len(store.flows))
	}
	// Re-arm on CH retransmit must stay idempotent.
	w.fastFailArm(pkt, ffVideoSet())

	// Server SYN-ACK/ACK arrives: first cum-ack observed.
	in := make([]byte, 40)
	in[0] = 0x45
	in[9] = 6
	copy(in[12:16], net.IPv4(203, 0, 113, 10).To4())
	copy(in[16:20], net.IPv4(192, 0, 2, 33).To4())
	binary.BigEndian.PutUint16(in[20:22], 443)
	binary.BigEndian.PutUint16(in[22:24], 51000)
	binary.BigEndian.PutUint32(in[28:32], 133) // frozen clamp point
	in[33] = 0x10
	w.fastFailObserveIncoming(in, 20, pkt.srcStr, 51000, pkt.dstStr, 443)

	// Client pushes data; below threshold nothing may happen.
	w.fastFailObserveOutbound(pkt, 0x18, fastFailBytesMin-1)
	if fake.sent4 != 0 {
		t.Fatalf("below byte threshold must not inject (got %d)", fake.sent4)
	}

	// Cross the threshold but stay inside T: still nothing.
	w.fastFailObserveOutbound(pkt, 0x18, 64)
	if fake.sent4 != 0 {
		t.Fatal("within stall window must not inject")
	}

	// Freeze past T: exactly one forged RST, SEQ == client's ACK.
	flow := store.flows[key]
	flow.lastAdvance = time.Now().Add(-fastFailStallT - 100*time.Millisecond)
	w.fastFailObserveOutbound(pkt, 0x18, 128)
	if fake.sent4 != 1 {
		t.Fatalf("stalled flow must forge one RST (got %d)", fake.sent4)
	}
	rst := fake.last4
	if got := binary.BigEndian.Uint32(rst[24:28]); got != 0xaa {
		t.Fatalf("forged seq=%#x want client ack 0xaa", got)
	}
	if rst[33] != 0x04 {
		t.Fatalf("flags=%#x want RST-only", rst[33])
	}

	// One-shot guard: further stalled observations are silent.
	w.fastFailObserveOutbound(pkt, 0x18, 512)
	if fake.sent4 != 1 {
		t.Fatal("second RST on same connKey is forbidden")
	}

	// FIN releases state; a fresh identical tuple may arm again.
	w.fastFailRelease(key)
	if len(store.flows) != 0 {
		t.Fatal("release must drop the flow entry")
	}

	// Dry-run default for a NEW worker/store: detection logs, no injection.
	fastFailLiveOnce = sync.Once{}
	fastFailLiveVal.Store(false)
	t.Setenv("B4_FASTFAIL_LIVE", "")
	sentBefore := fake.sent4
	w2 := &Worker{fastFail: newFastFailStore(), clientInjector: fake}
	pkt2 := ffSyntheticOutbound(t, 51001, nil, 0x18)
	w2.fastFailArm(pkt2, ffAPISet())
	w2.fastFailObserveIncoming(in, 20, pkt2.srcStr, 51001, pkt2.dstStr, 443)
	f2 := w2.fastFail.flows[fastFailConnKey(pkt2)]
	f2.bytesUnacked = fastFailBytesMin + 10
	f2.lastAdvance = time.Now().Add(-fastFailStallT - time.Second)
	w2.fastFailObserveOutbound(pkt2, 0x18, 256)
	if fake.sent4 != sentBefore {
		t.Fatal("dry-run must never inject")
	}
	if !f2.rstSent {
		t.Fatal("dry-run still consumes the one-shot guard to avoid log spam")
	}
}
