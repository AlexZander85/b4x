package nfq

// b4x-693 fast-fail: forged RST-to-client on stalled masked youtube-TCP flows.
//
// Parent context: b4x-jib stage 3 — TSPU byte-clamp (26.08 pcap): SYNs,
// SYN-ACKs and the first ~130–148 B of TCP payload toward youtube IPs pass;
// everything after is silently dropped and server cum-acks freeze (~133).
// QUIC/UDP is untouched, so Chrome hangs 30–60 s on doomed TCP flows to fresh
// rrN---sn-*.googlevideo.com hosts before Cronet falls back to live
// masked QUIC on its own.
//
// Mechanism — deliberately different from the CLOSED L-steer family
// (YOUTUBE_DATAPLANE §7: v1 `69b18178` preemptive RST at ECH-detect caused a
// retry storm of fresh tuples every 3–13 s; v2 silent SYN-drop put clients in
// TCP-limbo). Fast-fail never touches a living flow:
//
//   - ARM: only when masking actually fired (dropAndInjectHandshake) for an
//     eligible set (youtube-video | combo-timestamp);
//   - FIRE: only after the flow is demonstrably dead — at least one inbound
//     ACK seen post-arm (post-handshake guard), ≥ fastFailBytesMin UNACKNOWLEDGED
//     payload bytes sent since the last forward cum-ack advance, and the server
//     cum-ack frozen for fastFailStallT. Counting unacked-only (not lifetime
//     bytes) is deliberate: a healthy socket reused by Cronet after a >T idle
//     gap must never fire just because old bytes were once sent — its fresh
//     packet has a tiny unacked backlog and the next real ACK resets the clock.
//     The client was going to sit in RTO backoff anyway; fast-fail only
//     shortens its timeout so Cronet reaches QUIC in seconds;
//   - GUARDS (bd b4x-693 spec): one RST per connKey for the flow lifetime
//     (client TIME_WAIT makes tuple reuse within TTL impossible), rolling
//     per-dstIP RST budget, eligible sets only, dry-run by default with
//     injection enabled only via B4_FASTFAIL_LIVE=1.
//
// The triggering packet's own header feeds buildRSTToClientV4/V6 (BLK-6), so
// SEQ lands on the client's current ACK window edge and is accepted instantly.
// Outbound packets are accepted untouched after the RST: no drop, no hold —
// minimal active interference per the steer post-mortem.

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

const (
	// fastFailBytesMin: minimum UNACKNOWLEDGED client payload bytes since the
	// last forward cum-ack advance before a stall may be declared
	// (">=N bytes after CH" in bd b4x-693). Sized above one full-size segment
	// so a lone retransmit cannot fire it.
	fastFailBytesMin = 512
	// fastFailStallT: server cum-ack must be frozen this long ("not moved for
	// T ms"). 4 s keeps the UX gate (<5 s video start) reachable while being
	// far above normal inter-ACK jitter of a healthy GGC stream.
	fastFailStallT = 4 * time.Second
	// fastFailFlowTTL bounds idle entries; mirrors other stores' 120 s GC.
	fastFailFlowTTL = 120 * time.Second
	// fastFailMaxFlows caps memory like maxConnStateEntries does elsewhere.
	fastFailMaxFlows = 4096
	// Per-dstIP RST budget: at most fastFailRSTBudgetPerDst resets per
	// rolling fastFailBudgetWindow even if many parallel tuples stall at
	// once (Chrome opens up to ~6 tuples per media fetch).
	fastFailRSTBudgetPerDst = 5
	fastFailBudgetWindow    = time.Second
)

type fastFailFlow struct {
	setID string
	// armedAt/lastAdvance: lastAdvance starts at arming and moves only when
	// the server cum-ack advances forward; stall = now-lastAdvance >= T.
	armedAt time.Time
	// bytesUnacked: client payload sent since the last forward cum-ack
	// advance. Reset by every advance so healthy reuse-after-idle (old bytes
	// long acknowledged) can never satisfy the byte threshold.
	bytesUnacked uint64
	srvAck       uint32
	srvAckSeen   bool
	lastAdvance  time.Time
	rstSent      bool
}

type fastFailBudgetEntry struct {
	windowStart time.Time
	count       int
}

type fastFailStore struct {
	mu     sync.Mutex
	flows  map[string]*fastFailFlow
	budget map[string]*fastFailBudgetEntry
}

func newFastFailStore() *fastFailStore {
	return &fastFailStore{
		flows:  make(map[string]*fastFailFlow),
		budget: make(map[string]*fastFailBudgetEntry),
	}
}

var (
	fastFailLiveOnce sync.Once
	fastFailLiveVal  atomic.Bool
)

// fastFailLiveInjection reports whether forged RSTs may actually leave the
// box. Default (and every first field deploy) is dry-run: stalls are detected
// and logged with the [fastfail] marker but nothing is injected. Set
// B4_FASTFAIL_LIVE=1 to arm injection (read once at first use).
func fastFailLiveInjection() bool {
	fastFailLiveOnce.Do(func() {
		switch strings.ToLower(strings.TrimSpace(os.Getenv("B4_FASTFAIL_LIVE"))) {
		case "1", "true", "yes", "on":
			fastFailLiveVal.Store(true)
			log.Warnf("[fastfail] live RST injection ENABLED via B4_FASTFAIL_LIVE")
		default:
			log.Infof("[fastfail] dry-run mode: stalls will be logged only (B4_FASTFAIL_LIVE=1 enables RST)")
		}
	})
	return fastFailLiveVal.Load()
}

// fastFailSetEligible: exactly the two youtube TCP sets from bd b4x-693.
// Never youtube-ui, never GEO_DNS/Gmail-adjacent sets.
func fastFailSetEligible(set *config.SetConfig) bool {
	if set == nil {
		return false
	}
	switch set.Name {
	case "youtube-video", "combo-timestamp":
		return true
	}
	switch set.Id {
	case "9b31cb9b-2bdc-4435-bfd6-f7977dca4876", // youtube-video
		"211bf07f-6c56-42be-97ac-151f18face49": // combo-timestamp
		return true
	}
	return false
}

// fastFailConnKey builds the store key from an outbound pkt (client->server).
func fastFailConnKey(pkt *pktInfo) string {
	tcp := pkt.raw[pkt.ihl:]
	sport := binary.BigEndian.Uint16(tcp[0:2])
	dport := binary.BigEndian.Uint16(tcp[2:4])
	return fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
}

// fastFailArm records that masking fired for this flow (called from the single
// dropAndInjectHandshake funnel). Idempotent: CH retransmits keep the original
// arming time so the stall clock never restarts on retries.
func (w *Worker) fastFailArm(pkt *pktInfo, set *config.SetConfig) {
	if !fastFailEnabled || w == nil || w.fastFail == nil || pkt == nil || !fastFailSetEligible(set) {
		return
	}
	if len(pkt.raw) < pkt.ihl+TCPHeaderMinLen {
		return
	}
	key := fastFailConnKey(pkt)
	now := time.Now()

	w.fastFail.mu.Lock()
	defer w.fastFail.mu.Unlock()
	if len(w.fastFail.flows) >= fastFailMaxFlows {
		w.fastFail.gcLocked(now)
	}
	if _, ok := w.fastFail.flows[key]; ok {
		return
	}
	w.fastFail.flows[key] = &fastFailFlow{
		setID:       setName(set),
		armedAt:     now,
		lastAdvance: now,
	}
}

// fastFailObserveIncoming tracks server cum-ack progress on inbound
// server->client packets (HandleIncoming direction). Any forward movement of
// the ACK number proves the flow is alive; duplicate/dup-acks do not reset
// the stall clock (byte-clamp freezes acks at ~133 while dup-acks may repeat).
func (w *Worker) fastFailObserveIncoming(raw []byte, ihl int, clientStr string, cport uint16, serverStr string, sport uint16) {
	if !fastFailEnabled || w == nil || w.fastFail == nil || len(raw) < ihl+TCPHeaderMinLen {
		return
	}
	tcp := raw[ihl:]
	if tcp[13]&0x10 == 0 {
		return // need an ACK field to speak about a cum-ack
	}
	ack := binary.BigEndian.Uint32(tcp[8:12])
	key := fmt.Sprintf(connKeyFormat, clientStr, cport, serverStr, sport)

	w.fastFail.mu.Lock()
	defer w.fastFail.mu.Unlock()
	f, ok := w.fastFail.flows[key]
	if !ok {
		return
	}
	if !f.srvAckSeen {
		f.srvAck = ack
		f.srvAckSeen = true
		f.lastAdvance = time.Now()
		f.bytesUnacked = 0 // pre-arm backlog is acknowledged history now
		return
	}
	if ack != f.srvAck && int32(ack-f.srvAck) > 0 { // forward, wrap-safe
		f.srvAck = ack
		f.lastAdvance = time.Now()
		f.bytesUnacked = 0
	}
}

// fastFailStalled is the pure fire predicate: post-handshake (at least one
// server ACK observed since arming), enough client investment, frozen server.
func fastFailStalled(f *fastFailFlow, now time.Time) bool {
	if f.rstSent || !f.srvAckSeen {
		return false
	}
	if f.bytesUnacked < fastFailBytesMin {
		return false
	}
	return now.Sub(f.lastAdvance) >= fastFailStallT
}

// fastFailObserveOutbound accumulates post-arm client payload and fires the
// forged RST when the stall predicate holds. Never drops the packet.
func (w *Worker) fastFailObserveOutbound(pkt *pktInfo, tcpFlags byte, payloadLen int) {
	if !fastFailEnabled || w == nil || w.fastFail == nil || pkt == nil {
		return
	}
	isSyn := tcpFlags&0x02 != 0
	isFin := tcpFlags&0x01 != 0
	isRst := tcpFlags&0x04 != 0
	now := time.Now()
	key := fastFailConnKey(pkt)

	w.fastFail.mu.Lock()
	f, ok := w.fastFail.flows[key]
	if !ok {
		w.fastFail.mu.Unlock()
		return
	}
	if !isSyn && !isFin && !isRst && payloadLen > 0 {
		f.bytesUnacked += uint64(payloadLen)
	}
	if !fastFailStalled(f, now) {
		w.fastFail.mu.Unlock()
		return
	}
	f.rstSent = true // one RST per connKey, decided under the lock
	setID := f.setID
	w.fastFail.mu.Unlock()

	if !w.fastFail.budgetAllow(pkt.dstStr, now) {
		log.Warnf("[fastfail] dst budget exhausted for %s; no RST (%s set=%s)", pkt.dstStr, key, setID)
		return
	}

	log.LogConnection("TCP", setID, "", pkt.srcStr, 0, setID, pkt.dstStr, 443, pkt.srcMac, "", "fastfail")
	log.Warnf("[fastfail] stalled masked flow %s set=%s dst=%s (b4x-693)", key, setID, pkt.dstStr)

	if !fastFailLiveInjection() {
		return
	}
	log.Warnf("[fastfail] injecting forged RST to client %s:%d (live mode)",
		pkt.srcStr, binary.BigEndian.Uint16(pkt.raw[pkt.ihl:pkt.ihl+2]))
	switch pkt.ver {
	case IPv4:
		w.sendRSTToClientV4(pkt.raw, pkt.ihl, pkt.src, pkt.dst)
	case IPv6:
		w.sendRSTToClientV6(pkt.raw, pkt.src, pkt.dst)
	}
}

// fastFailRelease drops flow state on FIN/RST so a later tuple collision can
// never inherit stale guards.
func (w *Worker) fastFailRelease(connKey string) {
	if !fastFailEnabled || w == nil || w.fastFail == nil {
		return
	}
	w.fastFail.mu.Lock()
	defer w.fastFail.mu.Unlock()
	delete(w.fastFail.flows, connKey)
}

// budgetAllow enforces fastFailRSTBudgetPerDst per rolling second per dstIP.
func (s *fastFailStore) budgetAllow(dstIP string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.budget[dstIP]
	if !ok || now.Sub(b.windowStart) >= fastFailBudgetWindow {
		s.budget[dstIP] = &fastFailBudgetEntry{windowStart: now, count: 1}
		return true
	}
	if b.count >= fastFailRSTBudgetPerDst {
		return false
	}
	b.count++
	return true
}

// GC prunes expired flows; wired into the pool janitor ticker.
func (s *fastFailStore) GC(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
}

func (s *fastFailStore) gcLocked(now time.Time) {
	for k, f := range s.flows {
		if now.Sub(f.armedAt) > fastFailFlowTTL {
			delete(s.flows, k)
		}
	}
	if len(s.budget) > fastFailMaxFlows {
		for k, b := range s.budget {
			if now.Sub(b.windowStart) >= fastFailBudgetWindow {
				delete(s.budget, k)
			}
		}
	}
}
