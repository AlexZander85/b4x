package classifier

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func hintClient(ip string, vlan uint16) ClientKey {
	return ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr(ip), IfIndex: 2, VLAN: vlan}
}

func hintEvidence(client ClientKey, dst, domain, set string, source EvidenceSource, created, expires time.Time, generation uint64) Evidence {
	return Evidence{
		Source:        source,
		Client:        client,
		DestinationIP: netip.MustParseAddr(dst),
		L4Proto:       6,
		Domain:        domain,
		SetID:         set,
		Confidence:    80,
		CreatedAt:     created,
		ExpiresAt:     expires,
		ConfigGen:     generation,
	}
}

func TestHostHintStoreScopesSharedDestinationByClient(t *testing.T) {
	clk := clock.NewFixed(time.Unix(100, 0))
	store := NewHostHintStore(HostHintStoreConfig{MaxEntries: 8, MaxEntriesPerClient: 4, MaxCandidatesPerKey: 4}, clk)
	dst := "203.0.113.7"
	if err := store.Observe(hintEvidence(hintClient("192.0.2.10", 10), dst, "api.youtube.com", "api", EvidenceDNSAnswer, clk.Now(), clk.Now().Add(time.Minute), 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Observe(hintEvidence(hintClient("192.0.2.11", 10), dst, "video.googlevideo.com", "video", EvidenceDNSAnswer, clk.Now(), clk.Now().Add(time.Minute), 1)); err != nil {
		t.Fatal(err)
	}
	first := store.Lookup(hintClient("192.0.2.10", 10), netip.MustParseAddr(dst), 6)
	second := store.Lookup(hintClient("192.0.2.11", 10), netip.MustParseAddr(dst), 6)
	if len(first) != 1 || first[0].Domain != "api.youtube.com" || len(second) != 1 || second[0].Domain != "video.googlevideo.com" {
		t.Fatalf("shared destination leaked candidates: first=%+v second=%+v", first, second)
	}
}

func TestHostHintStoreKeepsMultipleCandidatesWithoutOverwriting(t *testing.T) {
	clk := clock.NewFixed(time.Unix(200, 0))
	store := NewHostHintStore(HostHintStoreConfig{MaxCandidatesPerKey: 4}, clk)
	client := hintClient("192.0.2.12", 10)
	for _, domain := range []string{"api.youtube.com", "www.youtube.com", "rr.googlevideo.com"} {
		if err := store.Observe(hintEvidence(client, "203.0.113.8", domain, domain, EvidenceDNSAnswer, clk.Now(), clk.Now().Add(time.Minute), 1)); err != nil {
			t.Fatal(err)
		}
	}
	got := store.Lookup(client, netip.MustParseAddr("203.0.113.8"), 6)
	if len(got) != 3 || got[0].Domain != "api.youtube.com" {
		t.Fatalf("candidates were not retained/sorted: %+v", got)
	}
}

func TestHostHintStoreTTLIsAbsoluteNotSliding(t *testing.T) {
	clk := clock.NewFixed(time.Unix(300, 0))
	store := NewHostHintStore(HostHintStoreConfig{}, clk)
	client := hintClient("192.0.2.13", 10)
	e := hintEvidence(client, "203.0.113.9", "api.youtube.com", "api", EvidenceDNSAnswer, clk.Now(), clk.Now().Add(10*time.Second), 1)
	if err := store.Observe(e); err != nil {
		t.Fatal(err)
	}
	clk.Advance(5 * time.Second)
	e.ExpiresAt = clk.Now().Add(time.Minute)
	if err := store.Observe(e); err != nil {
		t.Fatal(err)
	}
	clk.Advance(6 * time.Second)
	if got := store.Lookup(client, netip.MustParseAddr("203.0.113.9"), 6); len(got) != 0 {
		t.Fatalf("re-observation slid TTL: %+v", got)
	}
}

func TestHostHintStoreEvictionAndGenerationRevalidation(t *testing.T) {
	clk := clock.NewFixed(time.Unix(400, 0))
	store := NewHostHintStore(HostHintStoreConfig{MaxEntries: 2, MaxEntriesPerClient: 2, MaxCandidatesPerKey: 2}, clk)
	client := hintClient("192.0.2.14", 10)
	for i, domain := range []string{"weak.example", "strong.example", "new.example"} {
		e := hintEvidence(client, netip.MustParseAddr("203.0.113."+string(rune('1'+i))).String(), domain, domain, EvidenceDNSAnswer, clk.Now(), clk.Now().Add(time.Minute), uint64(i+1))
		if i == 1 {
			e.Confidence = 89
		}
		if err := store.Observe(e); err != nil {
			t.Fatal(err)
		}
	}
	if store.Stats().Entries != 2 {
		t.Fatalf("global bound not enforced: %+v", store.Stats())
	}
	if removed := store.InvalidateGeneration(2); removed != 1 {
		t.Fatalf("generation invalidation removed %d candidates", removed)
	}
	if got := store.LookupForGeneration(client, netip.MustParseAddr("203.0.113.2"), 6, 3); len(got) != 0 {
		t.Fatalf("stale generation remained visible: %+v", got)
	}
}

func TestHostHintStoreRejectsUnscopedAndUnsupportedEvidence(t *testing.T) {
	clk := clock.NewFixed(time.Unix(500, 0))
	store := NewHostHintStore(HostHintStoreConfig{}, clk)
	base := hintEvidence(hintClient("192.0.2.15", 10), "203.0.113.10", "api.youtube.com", "api", EvidenceDNSAnswer, clk.Now(), clk.Now().Add(time.Minute), 1)
	base.Client = ClientKey{}
	if !errors.Is(store.Observe(base), ErrUnscopedHostHint) {
		t.Fatal("unscoped hint was accepted")
	}
	base.Client = hintClient("192.0.2.15", 10)
	base.Source = EvidenceStaticIP
	if !errors.Is(store.Observe(base), ErrUnsupportedHintSource) {
		t.Fatal("static IP evidence was accepted as source-scoped host hint")
	}
}

func TestHostHintStoreGCDeleteAndStats(t *testing.T) {
	clk := clock.NewFixed(time.Unix(600, 0))
	store := NewHostHintStore(HostHintStoreConfig{}, clk)
	client := hintClient("192.0.2.16", 10)
	e := hintEvidence(client, "203.0.113.11", "api.youtube.com", "api", EvidenceDNSAnswer, clk.Now(), clk.Now().Add(time.Second), 1)
	if err := store.Observe(e); err != nil {
		t.Fatal(err)
	}
	if len(store.Lookup(client, e.DestinationIP, e.L4Proto)) != 1 {
		t.Fatal("hint was not found")
	}
	clk.Advance(2 * time.Second)
	if removed := store.GC(clk.Now()); removed != 1 || store.GC(clk.Now()) != 0 {
		t.Fatalf("GC was not idempotent: removed=%d", removed)
	}
	if store.DeleteClient(client) != 0 {
		t.Fatal("delete after GC removed unexpected state")
	}
	stats := store.Stats()
	if stats.Observed != 1 || stats.Lookups != 1 || stats.Hits != 1 || stats.Expired != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func BenchmarkHostHintStoreObserveLookup(b *testing.B) {
	clk := clock.NewFixed(time.Unix(700, 0))
	store := NewHostHintStore(HostHintStoreConfig{MaxEntries: 1024, MaxEntriesPerClient: 64, MaxCandidatesPerKey: 4}, clk)
	client := hintClient("192.0.2.17", 10)
	e := hintEvidence(client, "203.0.113.12", "api.youtube.com", "api", EvidenceDNSAnswer, clk.Now(), clk.Now().Add(time.Minute), 1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = store.Observe(e)
		_ = store.Lookup(client, e.DestinationIP, e.L4Proto)
	}
}
