package nfq

import (
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fixtures"
)

func echVideoSet() *config.SetConfig {
	return &config.SetConfig{Name: "youtube-video", Id: "9b31cb9b-2bdc-4435-bfd6-f7977dca4876"}
}

func newECHFlowTestWorker() (*Worker, *echFlowStore) {
	w := &Worker{}
	w.cfg.Store(&config.Config{})
	s := newECHFlowStore()
	w.echFlow = s
	return w, s
}

func TestECHFlowMarkFirstSightingOnly(t *testing.T) {
	s := newECHFlowStore()
	now := time.Now()

	if !s.markOrEnrich("k1", echFlowEntry{set: "youtube-video"}, now) {
		t.Fatal("first sighting must mark")
	}
	if s.markOrEnrich("k1", echFlowEntry{set: "youtube-video"}, now.Add(time.Second)) {
		t.Fatal("second sighting of the same flow must not re-mark")
	}
	if !s.markOrEnrich("k2", echFlowEntry{}, now) {
		t.Fatal("a different flow must mark independently")
	}
	// Empty keys are rejected (no flow identity -> no marker).
	if s.markOrEnrich("", echFlowEntry{}, now) {
		t.Fatal("empty key must not mark")
	}
}

// The metadata hook fires first on complete-in-one-segment CHs but knows
// neither set nor host nor size; the funnel observation of the same flow must
// fill those in silently instead of being starved by first-only marking.
func TestECHFlowEnrichesAfterPrematureMetadataMark(t *testing.T) {
	w, s := newECHFlowTestWorker()
	pkt := &pktInfo{srcStr: "192.168.1.152", dstStr: "173.194.6.6", srcMac: "22:30:F3:33:62:27"}

	w.observeECHFlowMeta(pkt, 41436, 443, classifier.TLSMetadata{ECHPresent: true, Version: 0x0303}, nil)
	key := "192.168.1.152:41436->173.194.6.6:443"
	if e := s.flows[key]; e.set != "" || e.host != "" || e.chBytes != -1 {
		t.Fatalf("premature entry mismatch: %+v", e)
	}

	payload := fixtures.BuildTLSClientHello("rr1---sn-4g5edndd.googlevideo.com", 0x0304, true, 1800)
	raw := ipv4TCPPacket(1000, payload)
	rawPkt := &pktInfo{
		raw: raw, ver: IPv4,
		src: []byte{192, 168, 1, 152}, dst: []byte{173, 194, 6, 6},
		srcStr: "192.168.1.152", dstStr: "173.194.6.6",
		srcMac: "22:30:F3:33:62:27", ihl: 20,
	}
	w.observeECHFlowRaw(rawPkt, raw, echVideoSet())

	e := s.flows[key]
	if len(s.flows) != 1 {
		t.Fatalf("enrichment must not duplicate entries, flows=%d", len(s.flows))
	}
	if e.set != "youtube-video" || e.host != "rr1---sn-4g5edndd.googlevideo.com" || e.chBytes != len(payload) {
		t.Fatalf("enriched entry mismatch: %+v", e)
	}
}

func TestECHFlowStoreEvictionAndSummaryShape(t *testing.T) {
	s := newECHFlowStore()
	now := time.Now()
	s.started = now.Add(-echSummaryEvery)

	s.markOrEnrich("192.168.1.152:40000->173.194.6.6:443", echFlowEntry{set: "youtube-video", chBytes: 1800}, now)
	s.markOrEnrich("192.168.1.152:40001->172.217.114.4:443", echFlowEntry{chBytes: -1}, now)

	s.mu.Lock()
	out := s.summaryLocked()
	s.mu.Unlock()
	for _, want := range []string{"[ech-flow]", "marked=2", "largeCH=1", "youtube-video=1", "unclassified=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary %q missing %q", out, want)
		}
	}

	// TTL expiry removes stale flows; a fresh one survives.
	later := now.Add(echFlowTTL + time.Second)
	s.sweep(later)
	s.mu.Lock()
	count := len(s.flows)
	s.mu.Unlock()
	if count != 0 {
		t.Fatalf("stale flows must expire on sweep, left=%d", count)
	}
}

func TestObserveECHFlowMetaRequiresECHAndMarksOnce(t *testing.T) {
	w, s := newECHFlowTestWorker()
	pkt := &pktInfo{srcStr: "192.168.1.152", dstStr: "173.194.6.6", srcMac: "22:30:F3:33:62:27"}

	// Clear-SNI metadata must never mark.
	w.observeECHFlowMeta(pkt, 41436, 443, classifier.TLSMetadata{HandshakeParsed: true}, echVideoSet())
	if len(s.flows) != 0 {
		t.Fatalf("non-ECH metadata must not mark, flows=%d", len(s.flows))
	}

	meta := classifier.TLSMetadata{ECHPresent: true, HandshakeParsed: true, Version: 0x0304}
	w.observeECHFlowMeta(pkt, 41436, 443, meta, echVideoSet())
	if len(s.flows) != 1 {
		t.Fatalf("ECH metadata must mark once, flows=%d", len(s.flows))
	}
	e := s.flows["192.168.1.152:41436->173.194.6.6:443"]
	if e.set != "youtube-video" || e.tls == "" {
		t.Fatalf("entry mismatch: %+v", e)
	}

	// Retransmit of the same flow is silent.
	w.observeECHFlowMeta(pkt, 41436, 443, meta, echVideoSet())
	if len(s.flows) != 1 {
		t.Fatalf("re-marking must be idempotent, flows=%d", len(s.flows))
	}

	// Nil worker / nil store guards.
	(&Worker{}).observeECHFlowMeta(nil, 0, 0, classifier.TLSMetadata{}, nil)
	var nilW *Worker
	nilW.observeECHFlowMeta(pkt, 0, 0, meta, nil)
}

func TestObserveECHFlowRawParsesAssembledCH(t *testing.T) {
	w, s := newECHFlowTestWorker()

	payload := fixtures.BuildTLSClientHello("rr1---sn-4g5edndd.googlevideo.com", 0x0304, true, 1800)
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

	w.observeECHFlowRaw(pkt, raw, echVideoSet())
	e, ok := s.flows["192.168.1.152:41436->173.194.6.6:443"]
	if !ok {
		t.Fatal("assembled ECH CH must be marked")
	}
	if e.host != "rr1---sn-4g5edndd.googlevideo.com" {
		t.Fatalf("host = %q, want ECH outer SNI", e.host)
	}
	if e.chBytes != len(payload) || e.set != "youtube-video" {
		t.Fatalf("entry mismatch: %+v", e)
	}

	// An ECH-free record never marks and never overwrites the entry.
	clean := ipv4TCPPacket(1001, fixtures.BuildTLSClientHello("www.example.com", 0x0304, false, 500))
	w.observeECHFlowRaw(pkt, clean, echVideoSet())
	if len(s.flows) != 1 {
		t.Fatalf("clean record must not mark, flows=%d", len(s.flows))
	}
}

func TestECHFlowHooksAreNoopWhenDisabled(t *testing.T) {
	if echFlowEnabled {
		t.Skip("enabled in echflow builds")
	}
	w := &Worker{}
	// nil store guards: these must not panic in default builds.
	w.observeECHFlowMeta(nil, 0, 0, classifier.TLSMetadata{}, nil)
	w.observeECHFlowRaw(nil, nil, nil)
}
