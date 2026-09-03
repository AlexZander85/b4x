package transportwarp

import (
	"context"
	"testing"
	"time"
)

// ---- M3-05: keep-old identity through throttle ----

// With a LIVE identity whose revalidation is throttled (429), the supervisor
// must adopt the kept identity and connect (keep-old dial) — NOT idle until
// the throttle lifts. "Throttle" means never re-enrolling, not stopping the
// tunnel; liveness is proven by the data plane.
func TestThrottledRevalidationKeepsIdentityAndConnects(t *testing.T) {
	h := newSupHarness(t)
	// Provision once so a valid, committed identity bound to the endpoint key
	// exists; then the revalidation of that kept account throttles forever.
	res, err := h.rec.Ensure(context.Background())
	if err != nil {
		t.Fatalf("seed provision: %v", err)
	}
	if res.Action != ActionProvisioned || res.Identity == nil {
		t.Fatalf("want provisioned, got %+v", res)
	}
	post, _, _, _, _ := h.api.counters()
	if post != 1 {
		t.Fatalf("seed must mint exactly one device, post=%d", post)
	}
	seedPost := post
	h.api.accountStatDef = 429

	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = time.Hour
		c.RevalidationInterval = time.Millisecond // revalidate on every identity phase
	})
	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Keep-old path must connect WITHOUT minting a new device: masque_connected
	// fires and the registration POST remains untouched.
	waitFor(t, 5*time.Second, "masque_connected via kept identity", func() bool {
		return countName(h.eventNames(), EvMasqueConnected) > 0
	})
	if post, _, _, _, _ := h.api.counters(); post != seedPost {
		t.Fatalf("throttled revalidation must never mint a NEW device (seed=%d), POST=%d", seedPost, post)
	}
	// And it must not sit in a pause: a session generation must have started.
	waitFor(t, 2*time.Second, "session generation started", func() bool {
		return countName(h.eventNames(), EvSessionGenerationStarted) > 0
	})
	sup.Stop()
}

// Throttle with NO identity (cold start, nothing to keep) must still pause
// and never dial — regression against the "no tunnel flywheel" guarantee.
func TestThrottleWithoutIdentityStillPausesNoDial(t *testing.T) {
	h := newSupHarness(t)
	h.api.postStatusDef = 429

	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.Sleep = h.recordSleep
	})
	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "identity-blocked event", func() bool {
		return countName(h.eventNames(), EvIdentityBlocked) > 0
	})
	// Wait a beat for any (erroneous) dial to surface.
	time.Sleep(300 * time.Millisecond)
	if conns, _ := h.mq.counters(); conns != 0 {
		t.Fatalf("no MASQUE dialing while identity blocked, connects=%d", conns)
	}
	if len(h.recordedSleeps()) == 0 {
		t.Fatal("no identity-cooldown wait recorded")
	}
	sup.Stop()
}
