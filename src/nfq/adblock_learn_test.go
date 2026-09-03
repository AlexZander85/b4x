// BLK-7a verification: the hot-path hand-off into IP-learn respects the CDN
// guard (service-set match ⇒ skip+counter) and otherwise enqueues exactly
// one learn request that the worker materializes through the bound applier.
package nfq

import (
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/adblock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sni"
)

type countingApplier struct {
	mu   sync.Mutex
	adds int
}

func (c *countingApplier) EnsureRules() error { return nil }
func (c *countingApplier) AddIPs(ips []net.IP, ttlSec int) error {
	c.mu.Lock()
	c.adds += len(ips)
	c.mu.Unlock()
	return nil
}
func (c *countingApplier) RemoveIPs(ips []net.IP) error { return nil }
func (c *countingApplier) Flush() error                 { return nil }

func (c *countingApplier) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.adds
}

func waitForLearnTotal(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if adblock.GetStats().IPLearnTotal >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ip_learn_total never reached %d (got %d)", want, adblock.GetStats().IPLearnTotal)
}

func TestMaybeLearnBlockedIPGuardsAndEnqueues(t *testing.T) {
	ap := &countingApplier{}
	adblock.SetLearnApplier(ap)
	t.Cleanup(func() {
		adblock.SetLearnApplier(nil)
		adblock.ConfigureLearn(config.AdBlockConfig{Enabled: false}, "")
	})

	svc := config.NewSetConfig()
	svc.Name = "svc"
	svc.Enabled = true
	svc.Targets.IpsToMatch = []string{"198.51.100.7"}
	matcher := sni.NewSuffixSet([]*config.SetConfig{&svc})

	adblock.ConfigureLearn(config.AdBlockConfig{
		Enabled:           true,
		IPLearn:           true,
		IPLearnTTLSec:     600,
		IPLearnMaxEntries: 100,
	}, filepath.Join(t.TempDir(), "iplearn.json"))
	defer adblock.ConfigureLearn(config.AdBlockConfig{Enabled: false}, "")

	if !adblock.LearnEnabled() {
		t.Fatal("precondition: learn sublayer must be running")
	}

	beforeCDN := adblock.GetStats().IPLearnCDNSkip
	w := &Worker{}

	// dst matches an existing service set: skip + counter, nothing learned.
	w.maybeLearnBlockedIP(matcher, "cdn.example.com", &pktInfo{
		dst: net.ParseIP("198.51.100.7"), srcMac: "AA:BB:CC:DD:EE:FF",
	}, "block")
	if got := adblock.GetStats().IPLearnCDNSkip; got != beforeCDN+1 {
		t.Fatalf("service-set collision must count as cdn skip: delta=%d", got-beforeCDN)
	}

	// Clean dst of a blocked domain: must reach the worker and the applier.
	w.maybeLearnBlockedIP(matcher, "ads.example.com", &pktInfo{
		dst: net.ParseIP("93.184.216.34"), srcMac: "AA:BB:CC:DD:EE:FF",
	}, "block")
	waitForLearnTotal(t, 1)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && ap.count() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if ap.count() == 0 {
		t.Fatal("worker must materialize the learned IP through the applier")
	}
}
