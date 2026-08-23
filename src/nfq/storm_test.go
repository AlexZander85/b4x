package nfq

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

func TestStormLevelBoundaries(t *testing.T) {
	cases := map[int]string{
		0:   "CALM",
		39:  "CALM",
		40:  "CHURN",
		79:  "CHURN",
		80:  "STORM",
		105: "STORM", // observed in the field 23.08
	}
	for n, want := range cases {
		if got := stormLevel(n); got != want {
			t.Fatalf("stormLevel(%d)=%q want %q", n, got, want)
		}
	}
}

func TestStormSnapshotPrunesWindow(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * stormWindow)
	stormG.mu.Lock()
	stormG.seen = map[string]time.Time{"1.1.1.1": old, "2.2.2.2": now, "3.3.3.3": now}
	stormG.mu.Unlock()

	if got := stormG.snapshot(now); got != 2 {
		t.Fatalf("unique=%d want 2 (expired must prune)", got)
	}
}

func TestGGCDiscSkipsVNBDeadShards(t *testing.T) {
	clk := time.Now()
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	set := config.NewSetConfig()
	set.Id = "youtube-video"
	set.Name = "youtube-video"
	set.Enabled = true
	set.Targets.DomainsToMatch = []string{"googlevideo.com"}
	cfg.Sets = []*config.SetConfig{&set}

	w := NewWorkerWithQueue(&cfg, 0)
	w.matcher.Store(buildMatcher(&cfg))
	w.ipToMac.Store(map[string]string{"192.0.2.50": "aa:bb:cc:dd:ee:50"})
	d := &ggcShardDiscovery{w: w, now: func() time.Time { return clk }}

	dead := netip.MustParseAddr("203.0.113.200")
	fresh := netip.MustParseAddr("203.0.113.201")
	vnbMark(dead, false, clk.Add(-time.Minute)) // fresh dead verdict

	shards := []ggcShard{
		{host: "r1.dead.example.googlevideo.com", addr: dead},
		{host: "r1.alive.example.googlevideo.com", addr: fresh},
	}
	clients := d.managedClients(&cfg)
	if len(clients) != 1 {
		t.Fatalf("clients=%d", len(clients))
	}
	fed := d.feed(&cfg, shards, clients)
	if fed != 2 { // only the alive shard, tcp+udp
		t.Fatalf("fed=%d, want 2 (dead shard must be skipped)", fed)
	}
	client, _ := dnsClientKey(net.ParseIP("192.0.2.50"), "aa:bb:cc:dd:ee:50")
	gen := dnsHintConfigGeneration(&cfg)
	if h := w.dnsHints.LookupForGeneration(client, dead, 6, gen); len(h) != 0 {
		t.Fatalf("dead shard hints leaked: %+v", h)
	}
	if h := w.dnsHints.LookupForGeneration(client, fresh, 6, gen); len(h) == 0 {
		t.Fatal("alive shard was not fed")
	}
}
