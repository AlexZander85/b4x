package nfq

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sni"
)

// tcp_has_ech flow classifier (Часть 3 П.2): mark a TCP flow doomed-by-policy
// the first time its ClientHello record carries an ECH extension.
//
// Field-proven model (YOUTUBE_DATAPLANE.md §2, 21→22.08): TSPU silently drops
// TCP-to-Google flows by the mere presence of the ECH extension in the CH
// record; phone Chromium/Cronet always sends ECH GREASE. The claim is the
// foundation for future ABD branching ("doomed by policy" vs "alive") — it
// must never act on the flow (steer v1/v2 field verdicts: interference is
// worse than natural fallback).
//
// Two observation points, both read-only:
//  1. handleTCPPacket, right after tcpTLSDecisionMetadata: catches any
//     complete-in-one-segment CH on a configured TCP port, regardless of set;
//  2. dropAndInjectHandshake funnel: catches hold-assembled split CHs (the
//     classic phone media class) for every resolved set.
//
// Limitation (by construction): a SPLIT CH that never resolves a set never
// assembles and therefore never reaches the funnel — its ECH stays unseen.
// That flow dies unclassified anyway; the gap is documented, not hidden.

const (
	echFlowMaxEntries = 1024
	echFlowTTL        = 15 * time.Minute
	echSummaryEvery   = 10 * time.Minute
)

type echFlowEntry struct {
	firstSeen time.Time
	set       string // set name at marking time ("" when not yet classified)
	host      string // SNI / ECH outer name when parseable ("" otherwise)
	chBytes   int    // ClientHello record bytes seen at marking time
	tls       string // max TLS version string
}

type echFlowStore struct {
	mu          sync.Mutex
	flows       map[string]echFlowEntry
	started     time.Time
	lastSummary time.Time
}

func newECHFlowStore() *echFlowStore {
	return &echFlowStore{
		flows:   make(map[string]echFlowEntry),
		started: time.Now(),
	}
}

// markOrEnrich records the first ECH sighting of a flow. Returns true when
// this call created the entry (caller logs the marker). A later, richer
// observation of an already-marked flow fills only the empty fields (the
// metadata path marks first with set/host/size unknown; the funnel path then
// supplies the resolved set, hostname and record size without a second log
// line). Instance creation itself is gated by echFlowEnabled
// (newRuntimeState), so default builds hold no state.
func (s *echFlowStore) markOrEnrich(key string, e echFlowEntry, now time.Time) bool {
	if s == nil || key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, seen := s.flows[key]; seen {
		if e.set != "" && existing.set == "" {
			existing.set = e.set
		}
		if e.host != "" && existing.host == "" {
			existing.host = e.host
		}
		if e.chBytes >= 0 && existing.chBytes < 0 {
			existing.chBytes = e.chBytes
		}
		if e.tls != "" && existing.tls == "" {
			existing.tls = e.tls
		}
		s.flows[key] = existing
		return false
	}
	if len(s.flows) >= echFlowMaxEntries {
		s.evictExpiredLocked(now)
	}
	if len(s.flows) >= echFlowMaxEntries {
		s.evictOldestLocked()
	}
	e.firstSeen = now
	s.flows[key] = e
	return true
}

func (s *echFlowStore) evictExpiredLocked(now time.Time) {
	for k, e := range s.flows {
		if now.Sub(e.firstSeen) > echFlowTTL {
			delete(s.flows, k)
		}
	}
}

func (s *echFlowStore) evictOldestLocked() {
	var oldest string
	var oldestT time.Time
	first := true
	for k, e := range s.flows {
		if first || e.firstSeen.Before(oldestT) {
			oldest, oldestT, first = k, e.firstSeen, false
		}
	}
	if !first {
		delete(s.flows, oldest)
	}
}

// sweep ages out stale flows and emits the throttled summary. Called from the
// worker GC tick like quicbound.sweep.
func (s *echFlowStore) sweep(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	for k, e := range s.flows {
		if now.Sub(e.firstSeen) > echFlowTTL {
			delete(s.flows, k)
		}
	}
	due := s.lastSummary.IsZero() || now.Sub(s.lastSummary) >= echSummaryEvery
	if due {
		s.lastSummary = now
	}
	out := ""
	if due && len(s.flows) > 0 {
		out = s.summaryLocked()
	}
	s.mu.Unlock()
	if out != "" {
		log.Warnf("%s", out)
	}
}

// summaryLocked renders window counts: total marked flows, per-set breakdown,
// share of large (split-assembled ≥1000 B) CHs. Caller holds s.mu.
func (s *echFlowStore) summaryLocked() string {
	sets := make(map[string]int)
	large := 0
	for _, e := range s.flows {
		name := e.set
		if name == "" {
			name = "unclassified"
		}
		sets[name]++
		if e.chBytes >= 1000 {
			large++
		}
	}
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", name, sets[name]))
	}
	return fmt.Sprintf("[ech-flow] marked=%d largeCH=%d sets(%s)",
		len(s.flows), large, strings.Join(parts, ","))
}

// ---- Worker hooks (observation-only) ----

// observeECHFlowMeta is hook 1: called from handleTCPPacket with the already
// computed decision metadata. Fires only on flows whose parsed CH shows ECH.
func (w *Worker) observeECHFlowMeta(pkt *pktInfo, sport, dport uint16, meta classifier.TLSMetadata, set *config.SetConfig) {
	if w == nil || w.echFlow == nil || pkt == nil || !meta.ECHPresent {
		return
	}
	key := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
	w.observeECHFlow(pkt, key, echFlowEntry{
		set:     setName(set),
		chBytes: -1, // size unknown at this point (metadata-only path)
		tls:     config.TLSVersionString(meta.Version),
	}, time.Now())
}

// observeECHFlowRaw is hook 2: called from the dropAndInjectHandshake funnel
// with the complete (possibly hold-assembled) packet. Parses the record to
// confirm ECH and enriches the entry with size/host before marking.
func (w *Worker) observeECHFlowRaw(pkt *pktInfo, raw []byte, set *config.SetConfig) {
	if w == nil || w.echFlow == nil || pkt == nil || len(raw) == 0 {
		return
	}
	var pi PacketInfo
	var ok bool
	if pkt.ver == IPv6 {
		pi, ok = ExtractPacketInfoV6(raw)
	} else {
		pi, ok = ExtractPacketInfoV4(raw)
	}
	if !ok || len(pi.Payload) < 6 || len(raw) < pi.IPHdrLen+4 {
		return
	}
	meta := sni.ParseTLSClientHelloMetadata(pi.Payload)
	if !meta.ECHPresent {
		return
	}
	sport := uint16(raw[pi.IPHdrLen])<<8 | uint16(raw[pi.IPHdrLen+1])
	dport := uint16(raw[pi.IPHdrLen+2])<<8 | uint16(raw[pi.IPHdrLen+3])
	key := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
	host := meta.ECHOuterName
	if host == "" {
		host = meta.SNI
	}
	w.observeECHFlow(pkt, key, echFlowEntry{
		set:     setName(set),
		host:    host,
		chBytes: len(pi.Payload),
		tls:     config.TLSVersionString(meta.MaxVersion),
	}, time.Now())
}

func (w *Worker) observeECHFlow(pkt *pktInfo, key string, e echFlowEntry, now time.Time) {
	if !w.echFlow.markOrEnrich(key, e, now) {
		return
	}
	log.Warnf("[ech-flow] src=%s dst=%s mac=%s set=%s host=%s ch=%dB tls=%s",
		pkt.srcStr, pkt.dstStr, pkt.srcMac, e.set, e.host, e.chBytes, e.tls)
}
