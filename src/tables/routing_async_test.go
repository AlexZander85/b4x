package tables

import (
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

// The async seam must never execute firewall commands from the test body:
// every job here uses a routing-disabled set, which routingAsyncApply
// filters before any exec. What the tests pin is the CONTRACT: submission
// drains, dedup refreshes on the IPTTL/2 horizon, and the skip verdict
// forgets after the TTL window.

func TestRoutingAsyncSubmitDrains(t *testing.T) {
	cfg := &config.Config{}
	set := &config.SetConfig{Id: "t-async", Name: "t-async"} // Routing zero => disabled
	RoutingHandleDNSAsync(cfg, set, []net.IP{net.IPv4(192, 0, 2, 10)})
	if !RoutingAsyncDrain(2 * time.Second) {
		t.Fatal("async queue did not drain within budget")
	}
}

func TestRoutingAsyncDedupWindow(t *testing.T) {
	RoutingAsyncReset()
	set := &config.SetConfig{Id: "t-dedup", Name: "t-dedup", Routing: config.RoutingConfig{
		Enabled:       true,
		IPTTLSeconds:  3600, // refresh window = 1800 s
	}}
	ip := net.IPv4(192, 0, 2, 11)
	now := time.Now()

	if RoutingAsyncSkipFreshForTest(set, ip, now) {
		t.Fatal("first application must not be skipped")
	}
	if !RoutingAsyncSkipFreshForTest(set, ip, now.Add(time.Minute)) {
		t.Fatal("re-apply inside the refresh window must be skipped")
	}
	// A different address is independent.
	if RoutingAsyncSkipFreshForTest(set, net.IPv4(192, 0, 2, 12), now.Add(time.Minute)) {
		t.Fatal("another address must not inherit the skip")
	}
	// After the TTL horizon the entry is stale again.
	if RoutingAsyncSkipFreshForTest(set, ip, now.Add(2*time.Hour)) {
		t.Fatal("entry older than TTL must be forgotten")
	}
	RoutingAsyncReset()
}

// RoutingAsyncSkipFreshForTest exposes the dedup decision with an injected
// clock (the production path uses time.Now internally).
func RoutingAsyncSkipFreshForTest(set *config.SetConfig, ip net.IP, now time.Time) bool {
	return routingAsyncSkipFresh(set, ip, now)
}
