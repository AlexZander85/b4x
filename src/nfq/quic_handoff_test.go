package nfq

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sni"
)

func TestQUICHandoffMirrorsSourceScopedUDPToTCP(t *testing.T) {
	clk := clock.NewFixed(time.Unix(800, 0))
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.QUICToTCPHandoffEnabled = true
	set := config.NewSetConfig()
	set.Id = "youtube-video"
	set.Name = "youtube-video"
	set.Enabled = true
	set.Targets.DomainsToMatch = []string{"rr.googlevideo.com"}
	cfg.Sets = []*config.SetConfig{&set}
	worker := NewWorkerWithQueue(&cfg, 0)
	worker.dnsHints = classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, clk)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 40), dst: net.IPv4(203, 0, 113, 40), srcMac: "aa:bb:cc:dd:ee:40"}
	worker.observeQUICHandoffAt(&cfg, pkt, 443, "rr.googlevideo.com", &set, clk.Now())
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.40"), SourceMAC: [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x40}}
	for _, protocol := range []uint8{17, 6} {
		hints := worker.dnsHints.LookupForGeneration(client, netip.MustParseAddr("203.0.113.40"), protocol, dnsHintConfigGeneration(&cfg))
		if len(hints) != 1 || hints[0].Source != classifier.EvidenceQUICSNI || hints[0].Domain != "rr.googlevideo.com" || hints[0].SetID != set.Id {
			t.Fatalf("protocol %d handoff hints=%+v", protocol, hints)
		}
	}
}

func TestQUICHandoffDoesNotLeakSharedIPBetweenClientsAndExpires(t *testing.T) {
	clk := clock.NewFixed(time.Unix(900, 0))
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.QUICToTCPHandoffEnabled = true
	set := config.NewSetConfig()
	set.Id = "youtube-api"
	set.Name = "youtube-api"
	set.Enabled = true
	cfg.Sets = []*config.SetConfig{&set}
	worker := NewWorkerWithQueue(&cfg, 0)
	worker.dnsHints = classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, clk)
	pktA := &pktInfo{src: net.IPv4(192, 0, 2, 41), dst: net.IPv4(203, 0, 113, 41), srcMac: "aa:bb:cc:dd:ee:41"}
	pktB := &pktInfo{src: net.IPv4(192, 0, 2, 42), dst: net.IPv4(203, 0, 113, 41), srcMac: "aa:bb:cc:dd:ee:42"}
	worker.observeQUICHandoffAt(&cfg, pktA, 443, "api.youtube.com", &set, clk.Now())
	worker.observeQUICHandoffAt(&cfg, pktB, 443, "other.example", &set, clk.Now())
	clientA, _ := dnsClientKey(pktA.src, pktA.srcMac)
	clientB, _ := dnsClientKey(pktB.src, pktB.srcMac)
	if len(worker.dnsHints.Lookup(clientA, netip.MustParseAddr("203.0.113.41"), 6)) != 1 || len(worker.dnsHints.Lookup(clientB, netip.MustParseAddr("203.0.113.41"), 6)) != 1 {
		t.Fatal("shared destination was not source-scoped")
	}
	clk.Advance(2 * time.Minute)
	if got := worker.dnsHints.Lookup(clientA, netip.MustParseAddr("203.0.113.41"), 6); len(got) != 0 {
		t.Fatalf("QUIC handoff TTL did not expire: %+v", got)
	}
}

func TestQUICHandoffFeatureGatePreservesLegacyGlobalPath(t *testing.T) {
	cfg := config.NewConfig()
	set := config.NewSetConfig()
	set.Id = "legacy"
	set.Name = "legacy"
	set.Enabled = true
	worker := NewWorkerWithQueue(&cfg, 0)
	worker.dnsHints = classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, clock.NewFixed(time.Unix(1000, 0)))
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 43), dst: net.IPv4(203, 0, 113, 43), srcMac: "aa:bb:cc:dd:ee:43"}
	worker.observeQUICHandoffAt(&cfg, pkt, 443, "legacy.example", &set, time.Unix(1000, 0))
	client, _ := dnsClientKey(pkt.src, pkt.srcMac)
	if got := worker.dnsHints.Lookup(client, netip.MustParseAddr("203.0.113.43"), 6); len(got) != 0 {
		t.Fatalf("disabled handoff wrote source-scoped hint: %+v", got)
	}
	matcher := sni.NewSuffixSet([]*config.SetConfig{&set})
	if matched, _, _ := matcher.MatchLearnedIPWithSource(pkt.dst, pkt.srcMac); matched {
		t.Fatal("handoff helper unexpectedly created global learned IP")
	}
}
