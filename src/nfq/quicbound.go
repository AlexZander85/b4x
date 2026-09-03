package nfq

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

// L-quicbound (Часть 2.5): TCP<->QUIC boundary sensors. Observation only —
// this file must never drop, reset, or otherwise act on traffic.

const (
	qbCorrelationWindow = 60 * time.Second  // QUIC "live nearby" window before an open
	qbFallbackWindow    = 120 * time.Second // max wait for the next QUIC burst after an open
	qbOpenTimeout       = 90 * time.Second  // no inbound FIN/RST within this -> fate=timeout
	qbMaxKeys           = 512
	qbMaxOpensPerKey    = 32
	qbSummaryEvery      = 10 * time.Minute
)

type qbOpen struct {
	ts        time.Time
	sport     uint16 // client source port (flow identity together with dstIP)
	mac       string
	echSeen   bool
	replays   int
	closed    bool
	closeTs   time.Time
	fate      string // "", "fin", "rst", "timeout"
	fallback  time.Duration
	hasFB     bool
	quicNear  bool // live QUIC to same dstIP within qbCorrelationWindow before ts
	newOrigin bool // host first seen in the observation window at confirm time
}

type qbKey struct {
	lastQUIC time.Time
	opens    []*qbOpen
	// refusedByMac counts SYN-stage refusals per device at this dstIP
	// (L-quicsynrst). Nil until the first refusal.
	refusedByMac map[string]int
}

type quicboundStore struct {
	mu                  sync.Mutex
	keys                map[string]*qbKey // dstIP -> state
	hosts               map[string]time.Time
	lastSummary         time.Time
	started             time.Time
	refusedTotal        int
	refusedSinceSummary int
}

func newQuicboundStore() *quicboundStore {
	return &quicboundStore{
		keys:    make(map[string]*qbKey),
		hosts:   make(map[string]time.Time),
		started: time.Now(),
	}
}

func (s *quicboundStore) keyLocked(ip string) *qbKey {
	k := s.keys[ip]
	if k == nil {
		if len(s.keys) >= qbMaxKeys {
			var oldest string
			var oldestT time.Time
			first := true
			for ip2, k2 := range s.keys {
				at := k2.lastQUIC
				if len(k2.opens) > 0 && k2.opens[len(k2.opens)-1].ts.After(at) {
					at = k2.opens[len(k2.opens)-1].ts
				}
				if first || at.Before(oldestT) {
					oldest, oldestT, first = ip2, at, false
				}
			}
			delete(s.keys, oldest)
		}
		k = &qbKey{}
		s.keys[ip] = k
	}
	return k
}

// noteQUIC records live masked-QUIC activity toward ip and stamps fallback
// on any pending ECH-confirmed open for that IP.
func (s *quicboundStore) noteQUIC(mac, ip string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keyLocked(ip)
	k.lastQUIC = now
	for i := len(k.opens) - 1; i >= 0; i-- {
		o := k.opens[i]
		if o.echSeen && !o.hasFB && !o.closed && now.Sub(o.ts) <= qbFallbackWindow {
			o.fallback = now.Sub(o.ts)
			o.hasFB = true
			break // first follow-up burst only
		}
	}
}

// openTCP records a bare outbound SYN toward a youtube-video IP.
func (s *quicboundStore) openTCP(mac, ip string, sport uint16, now time.Time) *qbOpen {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keyLocked(ip)
	near := !k.lastQUIC.IsZero() && now.Sub(k.lastQUIC) <= qbCorrelationWindow
	o := &qbOpen{ts: now, sport: sport, mac: mac, quicNear: near}
	k.opens = append(k.opens, o)
	if len(k.opens) > qbMaxOpensPerKey {
		k.opens = k.opens[len(k.opens)-qbMaxOpensPerKey:]
	}
	return o
}

// confirmECH marks the latest unclosed open of the flow as ECH-doomed and
// tracks whether its host was unseen before (new media-origin proxy). If no
// prior SYN-stage record exists (common: the set is only resolvable after
// the ClientHello), it creates one — a confirmed ECH handshake IS a doomed
// TCP open by definition.
func (s *quicboundStore) confirmECH(ip string, sport uint16, host string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keyLocked(ip)
	for i := len(k.opens) - 1; i >= 0; i-- {
		o := k.opens[i]
		if o.sport == sport && !o.closed {
			o.echSeen = true
			s.markHostLocked(o, host, now)
			return
		}
	}
	o := &qbOpen{
		ts:       now,
		sport:    sport,
		echSeen:  true,
		quicNear: !k.lastQUIC.IsZero() && now.Sub(k.lastQUIC) <= qbCorrelationWindow,
	}
	k.opens = append(k.opens, o)
	if len(k.opens) > qbMaxOpensPerKey {
		k.opens = k.opens[len(k.opens)-qbMaxOpensPerKey:]
	}
	s.markHostLocked(o, host, now)
}

func (s *quicboundStore) markHostLocked(o *qbOpen, host string, now time.Time) {
	if host == "" {
		return
	}
	first, seen := s.hosts[host]
	o.newOrigin = !seen || now.Sub(first) > time.Hour
	s.hosts[host] = now
}

// replay counts a hold-replay of the doomed handshake (client RTO).
func (s *quicboundStore) replay(ip string, sport uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keys[ip]
	if k == nil {
		return
	}
	for i := len(k.opens) - 1; i >= 0; i-- {
		o := k.opens[i]
		if o.sport == sport && !o.closed {
			o.replays++
			return
		}
	}
}

// closeTCP classifies flow fate from mirrored inbound control packets.
func (s *quicboundStore) closeTCP(ip string, sport uint16, fate string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keys[ip]
	if k == nil {
		return
	}
	for i := len(k.opens) - 1; i >= 0; i-- {
		o := k.opens[i]
		if o.sport == sport && !o.closed {
			o.closed = true
			o.closeTs = now
			o.fate = fate
			return
		}
	}
}

// sweep times out stale opens and emits the periodic summary. Safe to call
// from every worker GC tick; the summary itself is throttled.
func (s *quicboundStore) sweep(now time.Time) {
	s.mu.Lock()
	for _, k := range s.keys {
		for _, o := range k.opens {
			if !o.closed && now.Sub(o.ts) > qbOpenTimeout {
				o.closed = true
				o.closeTs = now
				o.fate = "timeout"
			}
		}
	}
	due := s.lastSummary.IsZero() || now.Sub(s.lastSummary) >= qbSummaryEvery
	if due {
		s.lastSummary = now
	}
	out := ""
	if due {
		out = s.summaryLocked(now)
	}
	s.mu.Unlock()
	if out != "" {
		log.Warnf("%s", out)
	}
}

func (s *quicboundStore) summaryLocked(now time.Time) string {
	windowStart := s.started
	if now.Sub(windowStart) < qbSummaryEvery {
		windowStart = now.Add(-qbSummaryEvery)
	}
	hours := now.Sub(windowStart).Hours()
	if hours <= 0 {
		hours = qbSummaryEvery.Hours() / 60
	}
	var opens, ech, near, newOrg, finN, rstN, toN, fb int
	var lifetimes, fbs []float64
	for _, k := range s.keys {
		for _, o := range k.opens {
			if o.ts.Before(windowStart) {
				continue
			}
			opens++
			if o.echSeen {
				ech++
			}
			if o.quicNear {
				near++
			}
			if o.newOrigin {
				newOrg++
			}
			switch o.fate {
			case "fin":
				finN++
			case "rst":
				rstN++
			case "timeout":
				toN++
			}
			end := o.closeTs
			if end.IsZero() {
				end = now
			}
			lifetimes = append(lifetimes, end.Sub(o.ts).Seconds())
			if o.hasFB {
				fbs = append(fbs, o.fallback.Seconds())
				fb++
			}
		}
	}
	pct := func(n int) string {
		if opens == 0 {
			return "n/a"
		}
		return fmt.Sprintf("%.0f%%", float64(n)/float64(opens)*100)
	}
	rate := "n/a"
	if opens > 0 {
		rate = fmt.Sprintf("%.1f", float64(opens)/hours)
	}
	return fmt.Sprintf(
		"[quicbound] opens=%d rate/h=%s ech=%s parallelQUIC(60s)=%s newOrigin=%s fate(fin/rst/timeout)=%d/%d/%d lifeMed=%.0fs fbSeen=%d/%d fbMed=%.0fs refused=%d(%d win,max/pair=%d)",
		opens, rate, pct(ech), pct(near), pct(newOrg), finN, rstN, toN,
		medianF(lifetimes), fb, opens, medianF(fbs),
		s.refusedSinceSummary, s.refusedTotal, s.maxRefusedPerPairLocked())
}

func medianF(v []float64) float64 {
	if len(v) == 0 {
		return -1
	}
	sort.Float64s(v)
	return v[len(v)/2]
}

// ---- Worker hooks (all observation-only) ----

func (w *Worker) quicboundNoteQUIC(pkt *pktInfo) {
	if w == nil || w.quicbound == nil || pkt == nil || pkt.ver != IPv4 {
		return
	}
	w.quicbound.noteQUIC(pkt.srcMac, pkt.dstStr, time.Now())
}

func (w *Worker) quicboundObserveOpen(pkt *pktInfo, set *config.SetConfig) {
	if w == nil || w.quicbound == nil || pkt == nil || pkt.ver != IPv4 || set == nil {
		return
	}
	tcp := pkt.raw[pkt.ihl:]
	if len(tcp) < 14 || tcp[13] != classifierFlagSYNOnly {
		return
	}
	o := w.quicbound.openTCP(pkt.srcMac, pkt.dstStr, binaryPort(tcp), time.Now())
	if o != nil && o.quicNear {
		log.Tracef("[quicbound] tcp-open with recent QUIC: %s:%d -> %s", pkt.srcStr, o.sport, pkt.dstStr)
	}
}

func (w *Worker) quicboundObserveHandshake(pkt *pktInfo, set *config.SetConfig, replay bool) {
	if w == nil || w.quicbound == nil || pkt == nil || pkt.ver != IPv4 || set == nil || !isYouTubeVideoSet(set) {
		return
	}
	ip := pkt.dstStr
	var sport uint16
	if len(pkt.raw) >= pkt.ihl+4 {
		sport = uint16(pkt.raw[pkt.ihl+0])<<8 | uint16(pkt.raw[pkt.ihl+1])
	}
	if replay {
		w.quicbound.replay(ip, sport)
		return
	}
	host := ""
	connKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dportFromRaw(pkt.raw, pkt.ihl))
	h, _, _ := w.tlsCache.Lookup(connKey)
	if h != "" {
		host = h
	}
	w.quicbound.confirmECH(ip, sport, host, time.Now())
}

func (w *Worker) quicboundObserveIncoming(set *config.SetConfig, clientIP string, clientPort uint16, isRst, isFin bool) {
	if w == nil || w.quicbound == nil || set == nil || !isYouTubeVideoSet(set) {
		return
	}
	switch {
	case isRst:
		w.quicbound.closeTCP(clientIP, clientPort, "rst", time.Now())
	case isFin:
		w.quicbound.closeTCP(clientIP, clientPort, "fin", time.Now())
	}
}

const classifierFlagSYNOnly = 0x02

func binaryPort(tcp []byte) uint16 {
	if len(tcp) < 2 {
		return 0
	}
	return uint16(tcp[0])<<8 | uint16(tcp[1])
}

func dportFromRaw(raw []byte, ihl int) uint16 {
	if len(raw) < ihl+4 {
		return 0
	}
	return uint16(raw[ihl+2])<<8 | uint16(raw[ihl+3])
}
