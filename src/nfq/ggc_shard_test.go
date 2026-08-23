package nfq

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
)

func ggcdiscFixtureBody() []byte {
	return []byte(`# report_mapping
some noise 192.168.1.1
rr5---sn-C0Q7LNZ7.googlevideo.com
r2---sn-jvhnu5g-c35k.googlevideo.com | edge
duplicate: rr5---sn-c0q7lnz7.googlevideo.com
not-a-shard r1.googlevideo.com
helper---sn-only123.googlevideo.com helper
`)
}

func ggcdiscShortCodeBody() []byte {
	return []byte(`188.18.149.69 => arn09s18 : router: "pr04.arn16" next_hop_address: "72.14.195.199" (188.18.149.0/25) [u]`)
}

func TestGGCDiscExtractShardHosts(t *testing.T) {
	hosts := ggcdiscExtractShardHosts(ggcdiscFixtureBody(), ggcdiscMaxHosts)
	want := []string{
		"rr5---sn-c0q7lnz7.googlevideo.com",
		"r2---sn-jvhnu5g-c35k.googlevideo.com",
		"helper---sn-only123.googlevideo.com",
	}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("hosts[%d] = %q, want %q", i, hosts[i], want[i])
		}
	}

	capped := ggcdiscExtractShardHosts([]byte(
		"a---sn-1.googlevideo.com b---sn-2.googlevideo.com c---sn-3.googlevideo.com"), 2)
	if len(capped) != 2 {
		t.Fatalf("cap broken: %v", capped)
	}

	// Region-dependent short-code form: bare POP code -> r1.<code> host;
	// literal "r1" is not a code; a full domain after "=>" passes through.
	short := ggcdiscExtractShardHosts(ggcdiscShortCodeBody(), ggcdiscMaxHosts)
	if len(short) != 1 || short[0] != "r1.arn09s18.googlevideo.com" {
		t.Fatalf("short-code hosts = %v", short)
	}
	mixed := ggcdiscExtractShardHosts([]byte("=> r1\n=> rr3.snc01.googlevideo.com"), ggcdiscMaxHosts)
	if len(mixed) != 1 || mixed[0] != "rr3.snc01.googlevideo.com" {
		t.Fatalf("mixed redirectee hosts = %v", mixed)
	}
}

func TestGGCDiscPublicIPv4Filter(t *testing.T) {
	cases := map[string]bool{
		"173.194.6.6":       true,
		"74.125.162.71":     true,
		"192.168.1.1":       false,
		"10.0.0.5":          false,
		"127.0.0.1":         false,
		"169.254.1.2":       false,
		"224.0.0.251":       false,
		"0.0.0.0":           false,
		"2001:4860:4860::88": false,
	}
	for raw, want := range cases {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", raw, err)
		}
		if got := ggcdiscPublicIPv4(addr); got != want {
			t.Fatalf("public(%s) = %v, want %v", raw, got, want)
		}
	}
}

func newGGCDiscTestWorker(cfg *config.Config) *ggcShardDiscovery {
	w := NewWorkerWithQueue(cfg, 0)
	w.matcher.Store(buildMatcher(cfg))
	return &ggcShardDiscovery{
		w:      w,
		now:    time.Now,
		fetch:  func(context.Context) ([]byte, error) { return nil, context.Canceled },
		resolve: func(context.Context, string) ([]netip.Addr, error) { return nil, context.Canceled },
	}
}

func TestGGCDiscFeedsScopedEvidenceForManagedClients(t *testing.T) {
	clk := clock.NewFixed(time.Unix(5000, 0))
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	set := config.NewSetConfig()
	set.Id = "youtube-video"
	set.Name = "youtube-video"
	set.Enabled = true
	set.Targets.DomainsToMatch = []string{"rr1---sn-x.googlevideo.com"}
	cfg.Sets = []*config.SetConfig{&set}

	d := newGGCDiscTestWorker(&cfg)
	d.now = clk.Now
	d.w.dnsHints = classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, clk)
	w := d.w
	w.ipToMac.Store(map[string]string{
		"192.0.2.40": "AA:BB:CC:DD:EE:40", // managed (case differs on purpose)
		"192.0.2.99": "11:22:33:44:55:99", // not managed
	})

	mac := strings.ToLower("AA:BB:CC:DD:EE:40")
	cfg.Queue.Devices.Enabled = true
	cfg.Queue.Devices.Devices = append(cfg.Queue.Devices.Devices,
		config.Device{MAC: strings.ToUpper(mac), Selected: true})

	shards := []ggcShard{{host: "rr1---sn-x.googlevideo.com", addr: netip.MustParseAddr("173.194.6.6")}}
	clients := d.managedClients(&cfg)
	if len(clients) != 1 || clients[0].mac != mac {
		t.Fatalf("managed clients = %+v, want only %s", clients, mac)
	}

	fed := d.feed(&cfg, shards, clients)
	if fed != 2 { // tcp + udp mirrors
		t.Fatalf("fed=%d, want 2", fed)
	}

	client := clients[0].key
	gen := dnsHintConfigGeneration(&cfg)
	for _, proto := range []uint8{6, 17} {
		hints := w.dnsHints.LookupForGeneration(client, netip.MustParseAddr("173.194.6.6"), proto, gen)
		if len(hints) != 1 {
			t.Fatalf("proto %d hints=%+v", proto, hints)
		}
		h := hints[0]
		if h.Source != classifier.EvidenceDNSAnswer ||
			h.Domain != "rr1---sn-x.googlevideo.com" ||
			h.SetID != "youtube-video" ||
			h.Confidence != ggcdiscConfidence ||
			h.ExpiresAt.Sub(clk.Now()) != ggcdiscTTL {
			t.Fatalf("proto %d hint mismatch: %+v", proto, h)
		}
	}
}

func TestGGCDiscCycleEndToEnd(t *testing.T) {
	clk := clock.NewFixed(time.Unix(6000, 0))
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	set := config.NewSetConfig()
	set.Id = "youtube-video"
	set.Name = "youtube-video"
	set.Enabled = true
	set.Targets.DomainsToMatch = []string{"googlevideo.com"}
	cfg.Sets = []*config.SetConfig{&set}

	d := newGGCDiscTestWorker(&cfg)
	d.now = clk.Now
	d.w.dnsHints = classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, clk)
	d.fetch = func(context.Context) ([]byte, error) {
		return []byte("=> rr1---sn-abc123.googlevideo.com\n"), nil
	}
	d.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "rr1---sn-abc123.googlevideo.com" {
			return nil, nil
		}
		return []netip.Addr{netip.MustParseAddr("74.125.162.71")}, nil
	}
	d.w.ipToMac.Store(map[string]string{"192.0.2.77": "aa:bb:cc:dd:ee:77"})

	d.cycle(context.Background(), &cfg)

	client, ok := dnsClientKey(net.ParseIP("192.0.2.77"), "aa:bb:cc:dd:ee:77")
	if !ok {
		t.Fatal("client key")
	}
	hints := d.w.dnsHints.LookupForGeneration(client, netip.MustParseAddr("74.125.162.71"), 6, dnsHintConfigGeneration(&cfg))
	if len(hints) == 0 {
		t.Fatal("end-to-end cycle produced no hints")
	}
}

func TestGGCDiscHooksAreNoopWhenDisabled(t *testing.T) {
	if ggcDiscEnabled {
		t.Skip("enabled in ggcdisc builds")
	}
	StartGGCShardDiscovery(nil, nil, nil) // must not panic
}
