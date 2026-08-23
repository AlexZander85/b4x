package nfq

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

// Cross-profile QUIC-bypass guard (Часть 3 П.3; z2k UPDATES.json:138 lesson,
// our steer v1/v2 field verdicts): when live masked-QUIC is observed toward a
// destination (or its shard hostname), ANY reaction to that destination's
// TCP failures must be suppressed — interference is always worse than the
// client's natural fallback. There are no reactors today; this layer builds
// the predicate and counts "would-suppress" events on doomed youtube-video
// flows so future ABD strategies inherit field-proven suppression data.

const (
	qbpWindow        = 60 * time.Second
	qbpMaxIPs        = 1024
	qbpMaxHosts      = 512
	qbpSummaryEvery  = 10 * time.Minute
)

type qbpStore struct {
	mu                 sync.Mutex
	ips                map[string]time.Time
	hosts              map[string]time.Time
	wouldSuppressWin   int
	wouldSuppressTotal int
	started            time.Time
	lastSummary        time.Time
}

func newQBPStore() *qbpStore {
	return &qbpStore{
		ips:     make(map[string]time.Time),
		hosts:   make(map[string]time.Time),
		started: time.Now(),
	}
}

func (s *qbpStore) noteIP(ip string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ips) >= qbpMaxIPs {
		s.pruneLocked(now)
	}
	s.ips[ip] = now
}

func (s *qbpStore) noteHost(host string, now time.Time) {
	if host == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hosts) >= qbpMaxHosts {
		s.hosts = make(map[string]time.Time)
	}
	s.hosts[strings.ToLower(host)] = now
}

// alive reports whether QUIC was seen toward ip OR host within qbpWindow.
func (s *qbpStore) alive(ip, host string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts, ok := s.ips[ip]; ok && now.Sub(ts) <= qbpWindow {
		return true
	}
	if host != "" {
		if ts, ok := s.hosts[strings.ToLower(host)]; ok && now.Sub(ts) <= qbpWindow {
			return true
		}
	}
	return false
}

func (s *qbpStore) pruneLocked(now time.Time) {
	for ip, ts := range s.ips {
		if now.Sub(ts) > qbpWindow {
			delete(s.ips, ip)
		}
	}
	for h, ts := range s.hosts {
		if now.Sub(ts) > qbpWindow {
			delete(s.hosts, h)
		}
	}
}

func (s *qbpStore) event(now time.Time) {
	s.mu.Lock()
	s.wouldSuppressWin++
	s.wouldSuppressTotal++
	s.mu.Unlock()
	_ = now
}

func (s *qbpStore) sweep(now time.Time) {
	s.mu.Lock()
	due := s.lastSummary.IsZero() || now.Sub(s.lastSummary) >= qbpSummaryEvery
	if due {
		s.lastSummary = now
	}
	out := ""
	if due {
		out = fmt.Sprintf("[qbp] window=%v ips=%d hosts=%d wouldSuppress=%d total=%d",
			qbpWindow, len(s.ips), len(s.hosts), s.wouldSuppressWin, s.wouldSuppressTotal)
		s.wouldSuppressWin = 0
	}
	s.mu.Unlock()
	if out != "" {
		log.Warnf("%s", out)
	}
}

// ---- Worker hooks ----

// qbpNoteIP records live masked-QUIC toward an IP (called from the UDP fake
// path where real QUIC flows pass masked).
func (w *Worker) qbpNoteIP(pkt *pktInfo) {
	if w == nil || w.qbp == nil || pkt == nil || pkt.ver != IPv4 {
		return
	}
	w.qbp.noteIP(pkt.dstStr, time.Now())
}

// qbpObserveDoomed counts doomed youtube-video handshakes whose destination
// has live QUIC — the exact events a future TCP-fail reactor must suppress.
func (w *Worker) qbpObserveDoomed(pkt *pktInfo, set *config.SetConfig) {
	if w == nil || w.qbp == nil || pkt == nil || set == nil || !isYouTubeVideoSet(set) {
		return
	}
	if !w.qbp.alive(pkt.dstStr, "", time.Now()) {
		return
	}
	w.qbp.event(time.Now())
	log.Tracef("[qbp] would-suppress doomed flow %s -> %s (QUIC alive)", pkt.srcStr, pkt.dstStr)
}

// QBPSuppressReaction is the predicate future ABD reactors must consult:
// true = QUIC fallback is alive for this destination, do NOT react to TCP
// failures (steer v1/v2 field verdict: any interference only delays it).
func (w *Worker) QBPSuppressReaction(dstIP string) bool {
	if w == nil || w.qbp == nil {
		return false
	}
	return w.qbp.alive(dstIP, "", time.Now())
}
