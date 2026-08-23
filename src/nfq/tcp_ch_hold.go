package nfq

import (
	"net"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sock"
)

const (
	chHoldWaitTTL      = 80 * time.Millisecond
	chHoldAssembledTTL = 2 * time.Minute
	chHoldMaxRecord    = 8192
	chHoldMaxFlows     = 256
)

type chHoldDecision int

const (
	chHoldNone chHoldDecision = iota
	chHoldWaiting
	chHoldReady
)

type chHoldEntry struct {
	key       string
	gen       uint64
	seq       uint32
	payload   []byte
	firstRaw  []byte
	ver       uint8
	dst       net.IP
	set       *config.SetConfig
	assembled []byte
	waiting   bool
	deadline  time.Time
	cachedAt  time.Time
}

type chHoldStore struct {
	mu      sync.Mutex
	nextGen uint64
	flows   map[string]*chHoldEntry
}

func newCHHoldStore() *chHoldStore {
	return &chHoldStore{flows: make(map[string]*chHoldEntry)}
}

func (s *chHoldStore) dropStaleContinuation(key string, seq uint32) bool {
	if s == nil || key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.flows[key]
	return e != nil && !e.waiting && e.assembled != nil && e.seq != seq
}

func (s *chHoldStore) cached(key string, seq uint32) []byte {
	if s == nil || key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.flows[key]
	if e == nil || e.waiting || e.assembled == nil || e.seq != seq {
		return nil
	}
	return append([]byte(nil), e.assembled...)
}

func (s *chHoldStore) start(key string, seq uint32, pkt *pktInfo, payload []byte, set *config.SetConfig) (gen uint64, ok bool) {
	if s == nil || key == "" || pkt == nil || len(payload) == 0 {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.flows) >= chHoldMaxFlows {
		s.evictOldestLocked()
	}
	s.nextGen++
	e := &chHoldEntry{
		key:      key,
		gen:      s.nextGen,
		seq:      seq,
		payload:  append([]byte(nil), payload...),
		firstRaw: append([]byte(nil), pkt.raw...),
		ver:      pkt.ver,
		dst:      append(net.IP(nil), pkt.dst...),
		set:      set,
		waiting:  true,
		deadline: time.Now().Add(chHoldWaitTTL),
	}
	s.flows[key] = e
	return e.gen, true
}

func (s *chHoldStore) append(key string, seq uint32, payload []byte) (assembled []byte, gen uint64, ok bool) {
	if s == nil || key == "" || len(payload) == 0 {
		return nil, 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.flows[key]
	if e == nil || !e.waiting {
		return nil, 0, false
	}
	end := e.seq + uint32(len(e.payload))
	switch {
	case seq == e.seq:
		if len(payload) > len(e.payload) {
			e.payload = append(e.payload[:0], payload...)
		}
		e.deadline = time.Now().Add(chHoldWaitTTL)
		s.nextGen++
		e.gen = s.nextGen
		return nil, e.gen, true
	case seq < e.seq || seq > end:
		return nil, 0, false
	default:
		skip := int(end - seq)
		if skip >= len(payload) {
			e.deadline = time.Now().Add(chHoldWaitTTL)
			s.nextGen++
			e.gen = s.nextGen
			return nil, e.gen, true
		}
		e.payload = append(e.payload, payload[skip:]...)
	}
	if len(e.payload) > chHoldMaxRecord {
		delete(s.flows, key)
		return nil, 0, false
	}
	if tlsHandshakeRecordIncomplete(e.payload) {
		e.deadline = time.Now().Add(chHoldWaitTTL)
		s.nextGen++
		e.gen = s.nextGen
		return nil, e.gen, true
	}
	pkt, built := rebuildHeldHandshake(e.firstRaw, e.payload)
	if !built {
		e.deadline = time.Now().Add(chHoldWaitTTL)
		s.nextGen++
		e.gen = s.nextGen
		return nil, e.gen, true
	}
	e.assembled = pkt
	e.waiting = false
	e.cachedAt = time.Now()
	s.nextGen++
	e.gen = s.nextGen
	e.payload = nil
	return append([]byte(nil), pkt...), e.gen, true
}

func (s *chHoldStore) takeInProgress(key string, gen uint64) *chHoldEntry {
	if s == nil || key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.flows[key]
	if e == nil || !e.waiting || e.gen != gen {
		return nil
	}
	delete(s.flows, key)
	return e
}

func (s *chHoldStore) discard(key string) {
	if s == nil || key == "" {
		return
	}
	s.mu.Lock()
	delete(s.flows, key)
	s.mu.Unlock()
}

func (s *chHoldStore) takeAllWaiting() []*chHoldEntry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*chHoldEntry, 0)
	for k, e := range s.flows {
		if e.waiting {
			out = append(out, e)
			delete(s.flows, k)
		}
	}
	return out
}

func (s *chHoldStore) gc(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.flows {
		if e.waiting && now.After(e.deadline.Add(time.Second)) {
			delete(s.flows, k)
			continue
		}
		if !e.waiting && e.assembled != nil && now.Sub(e.cachedAt) >= chHoldAssembledTTL {
			delete(s.flows, k)
		}
	}
}

func (s *chHoldStore) evictOldestLocked() {
	var oldest string
	var t time.Time
	first := true
	for k, e := range s.flows {
		at := e.deadline
		if !e.waiting {
			at = e.cachedAt
		}
		if first || at.Before(t) {
			oldest, t, first = k, at, false
		}
	}
	if !first {
		delete(s.flows, oldest)
	}
}

func rebuildHeldHandshake(firstRaw, payload []byte) ([]byte, bool) {
	if len(firstRaw) == 0 || len(payload) == 0 {
		return nil, false
	}
	switch firstRaw[0] >> 4 {
	case IPv4:
		pi, ok := ExtractPacketInfoV4(firstRaw)
		if !ok {
			return nil, false
		}
		seg := BuildSegmentV4(firstRaw, pi, payload, 0, 0)
		SetPSH(seg, pi.IPHdrLen)
		sock.FixIPv4Checksum(seg[:pi.IPHdrLen])
		sock.FixTCPChecksum(seg)
		return seg, true
	case IPv6:
		pi, ok := ExtractPacketInfoV6(firstRaw)
		if !ok {
			return nil, false
		}
		seg := BuildSegmentV6(firstRaw, pi, payload, 0)
		SetPSH(seg, pi.IPHdrLen)
		sock.FixTCPChecksumV6(seg)
		return seg, true
	default:
		return nil, false
	}
}

func (s *chHoldStore) setOf(key string) *config.SetConfig {
	if s == nil || key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.flows[key]; e != nil {
		return e.set
	}
	return nil
}

// continueCHHold finishes a waiting hold. The ECH tail is not 0x16 and often
// has no SNI, so the packet is unmatched — it must still append.
func (w *Worker) continueCHHold(key string, seq uint32, payload []byte, dstStr string) (chHoldDecision, []byte, *config.SetConfig, bool) {
	if w == nil || w.chHold == nil || key == "" || len(payload) == 0 {
		return chHoldNone, nil, nil, false
	}
	if assembled := w.chHold.cached(key, seq); assembled != nil {
		log.Tracef("hold replay assembled TLS handshake (%d B) to %s", len(assembled), dstStr)
		return chHoldReady, assembled, w.chHold.setOf(key), true
	}
	if w.chHold.dropStaleContinuation(key, seq) {
		return chHoldWaiting, nil, nil, false
	}
	assembled, gen, ok := w.chHold.append(key, seq, payload)
	if !ok {
		return chHoldNone, nil, nil, false
	}
	if assembled != nil {
		log.Tracef("hold assembled TLS handshake record (%d B) to %s", len(assembled), dstStr)
		return chHoldReady, assembled, w.chHold.setOf(key), false
	}
	w.armCHHoldTimer(key, gen)
	return chHoldWaiting, nil, nil, false
}

func (w *Worker) considerCHHold(key string, seq uint32, pkt *pktInfo, payload []byte, set *config.SetConfig) (chHoldDecision, []byte, bool) {
	if w == nil || w.chHold == nil || key == "" || pkt == nil || len(payload) == 0 {
		return chHoldNone, nil, false
	}
	if dec, assembled, _, replay := w.continueCHHold(key, seq, payload, pkt.dstStr); dec != chHoldNone {
		return dec, assembled, replay
	}
	if set == nil {
		return chHoldNone, nil, false
	}
	total := tlsHandshakeRecordTotal(payload)
	if total <= len(payload) || total > chHoldMaxRecord {
		return chHoldNone, nil, false
	}
	gen, ok := w.chHold.start(key, seq, pkt, payload, set)
	if !ok {
		return chHoldNone, nil, false
	}
	log.Tracef("hold incomplete TLS handshake record (%d B, need %d) to %s", len(payload), total-len(payload), pkt.dstStr)
	w.armCHHoldTimer(key, gen)
	return chHoldWaiting, nil, false
}

func (w *Worker) armCHHoldTimer(key string, gen uint64) {
	if w == nil || w.chHold == nil || key == "" || gen == 0 || w.ctx == nil {
		return
	}
	time.AfterFunc(chHoldWaitTTL, func() {
		select {
		case <-w.ctx.Done():
			return
		default:
		}
		e := w.chHold.takeInProgress(key, gen)
		if e == nil {
			return
		}
		w.flushCHHoldFallback(e)
	})
}

func (w *Worker) flushCHHoldFallback(e *chHoldEntry) {
	if w == nil || e == nil {
		return
	}
	raw, ok := rebuildHeldHandshake(e.firstRaw, e.payload)
	if !ok {
		raw = e.firstRaw
	}
	log.Tracef("hold timeout; fake-only flush %d B to %s", len(e.payload), net.IP(e.dst).String())
	if e.set != nil && e.set.Faking.SNI && e.set.Faking.SNISeqLength > 0 {
		if e.ver == IPv6 {
			w.sendFakeSNISequencev6(e.set, raw, e.dst)
		} else {
			w.sendFakeSNISequence(e.set, raw, e.dst)
		}
	}
	if w.sock == nil {
		return
	}
	if e.ver == IPv6 {
		_ = w.sock.SendIPv6(raw, e.dst)
		return
	}
	_ = w.sock.SendIPv4(raw, e.dst)
}

func (w *Worker) dropAndInjectHandshake(vc *verdictCtx, pkt *pktInfo, set *config.SetConfig, raw []byte, replay bool) int {
	// tcp_has_ech (Часть 3 П.2): observation-only claim on the complete
	// (possibly hold-assembled) record. Runs before any consumer of the
	// handshake so the marker reflects the first ECH sighting.
	if echFlowEnabled {
		w.observeECHFlowRaw(pkt, raw, set)
	}
		if qbpEnabled {
			w.qbpObserveDoomed(pkt, set)
		}
		if ja4Enabled {
			w.ja4ObserveHandshake(pkt, raw, set)
		}
	// L-steer (b4x-p0.8): a youtube-video flow whose record carries ECH is
	// doomed on GGC (TSPU cuts by ECH-ext presence); RST the client instead
	// of injecting so Cronet falls back to masked QUIC.
	if w.maybeSteerECHFlow(vc, pkt, set, raw) {
		return 0
	}
	// tlsrec-diag (b4x-z1h): diagnostic build only — re-frame the assembled
	// youtube-video ECH CH into two TLS records and send them as plain
	// segments. Pcap verdict: ServerHello from GGC = TSPU fails on
	// multi-record ClientHellos. Default builds compile this to no-op.
	if w.maybeTLSRecDiagnose(vc, pkt, set, raw, replay) {
		return 0
	}
	// ipfrag2-diag: ipfragdiag builds only — cut the assembled ECH CH into
	// two IPv4 fragments (disorder). No seq problem by construction; pcap
	// verdict: inbound data from GGC = reassembly gap found.
	if w.maybeIPFrag2Diagnose(vc, pkt, set, raw, replay) {
		return 0
	}
	// L-quicbound (Часть 2.5): observation-only doomed-handshake markers
	// (ECH confirmed + client RTO replays). Never acts on the packet.
	if quicboundEnabled {
		w.quicboundObserveHandshake(pkt, set, replay)
	}
	// L-quicsynrst (Часть 2.6): arm/re-arm the (device,dstIP) scope after a
	// classified doomed flow. The triggering flow proceeds normally.
	if quicSynRstEnabled {
		w.maybeArmQuicSynRst(pkt, set, raw)
	}
	packetCopy := append([]byte(nil), raw...)
	if set.TCP.DropSACK {
		if pkt.ver == IPv4 {
			packetCopy = sock.StripSACKFromTCP(packetCopy)
		} else {
			packetCopy = sock.StripSACKFromTCPv6(packetCopy)
		}
	}
	dstCopy := append(net.IP(nil), pkt.dst...)
	setCopy := set
	if !vc.drop() {
		return 0
	}
	v := pkt.ver
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		// C only youtube-video. headmss (pos=1+MSS) had no 0x17 on GGC.
		// Next: same geometry + seqovl=681 on the 1-byte head (z2k gv_tcp).
		if shouldInjectHeadMSS(setCopy, handshakePayloadLen(packetCopy)) {
			if v == IPv4 {
				w.injectCSeqovl(setCopy, packetCopy, dstCopy, replay)
			} else {
				w.injectCSeqovlv6(setCopy, packetCopy, dstCopy, replay)
			}
			return
		}
		if v == IPv4 {
			w.dropAndInjectTCP(setCopy, packetCopy, dstCopy)
		} else {
			w.dropAndInjectTCPv6(setCopy, packetCopy, dstCopy)
		}
	}()
	return 0
}