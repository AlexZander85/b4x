package nfq

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
)

func TestScopedDNSHintSelectsSetForImmediateTCPFlow(t *testing.T) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.ScopedDNSHintsEnabled = true
	set := config.NewSetConfig()
	set.Id = "youtube-api"
	set.Name = "youtube-api"
	set.Enabled = true
	set.Targets.DomainsToMatch = []string{"api.youtube.com"}
	cfg.Sets = []*config.SetConfig{&set}
	worker := NewWorkerWithQueue(&cfg, 0)
	worker.matcher.Store(buildMatcher(&cfg))

	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.30")}
	destination := netip.MustParseAddr("203.0.113.30")
	if err := worker.dnsHints.Observe(classifier.Evidence{
		Source:          classifier.EvidenceDNSAnswer,
		Client:          client,
		DestinationIP:   destination,
		DestinationPort: 443,
		L4Proto:         6,
		Domain:          "api.youtube.com",
		SetID:           set.Id,
		Confidence:      89,
		DomainEvidence:  true,
		SourceDevice:    "",
		CreatedAt:       time.Now().Add(-time.Second),
		ExpiresAt:       time.Now().Add(time.Minute),
		ConfigGen:       dnsHintConfigGeneration(&cfg),
	}); err != nil {
		t.Fatal(err)
	}
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 30), dst: net.IPv4(203, 0, 113, 30), srcMac: ""}
	got, ok := worker.matchScopedDNSHint(&cfg, pkt, 51000, 443, 6)
	if !ok || got != &set {
		t.Fatalf("scoped hint did not select set: got=%v ok=%v", got, ok)
	}
}

func TestScopedDNSHintsInvalidateOnRuntimeGenerationChange(t *testing.T) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.ScopedDNSHintsEnabled = true
	set := config.NewSetConfig()
	set.Id = "youtube-video"
	set.Name = "youtube-video"
	set.Enabled = true
	set.Targets.DomainsToMatch = []string{"rr.googlevideo.com"}
	cfg.Sets = []*config.SetConfig{&set}
	worker := NewWorkerWithQueue(&cfg, 0)
	worker.matcher.Store(buildMatcher(&cfg))
	pool := &Pool{Workers: []*Worker{worker}}
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.31")}
	if err := worker.dnsHints.Observe(classifier.Evidence{
		Source:         classifier.EvidenceDNSAnswer,
		Client:         client,
		DestinationIP:  netip.MustParseAddr("203.0.113.31"),
		L4Proto:        6,
		Domain:         "rr.googlevideo.com",
		SetID:          set.Id,
		Confidence:     89,
		DomainEvidence: true,
		CreatedAt:      time.Now().Add(-time.Second),
		ExpiresAt:      time.Now().Add(time.Minute),
		ConfigGen:      dnsHintConfigGeneration(&cfg),
	}); err != nil {
		t.Fatal(err)
	}
	updated := cfg.CloneForRuntimeUpdate()
	updated.System.Classifier.Flags.ScopedDNSHintsEnabled = true
	if err := pool.UpdateConfig(updated); err != nil {
		t.Fatal(err)
	}
	if got := worker.dnsHints.Lookup(client, netip.MustParseAddr("203.0.113.31"), 6); len(got) != 0 {
		t.Fatalf("old generation hint survived update: %+v", got)
	}
}

func TestDNSClientKeySupportsIPOnlyAndMACIdentity(t *testing.T) {
	key, ok := dnsClientKey(net.IPv4(192, 0, 2, 32), "aa:bb:cc:dd:ee:ff")
	if !ok || key.L3Family != 4 || key.SourceIP != netip.MustParseAddr("192.0.2.32") || key.SourceMAC != [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Fatalf("IPv4 client key = %+v ok=%v", key, ok)
	}
	key, ok = dnsClientKey(net.ParseIP("2001:db8::32"), "")
	if !ok || key.L3Family != 6 || key.SourceMAC != [6]byte{} {
		t.Fatalf("IPv6 IP-only client key = %+v ok=%v", key, ok)
	}
}
