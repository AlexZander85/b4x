// Supervisor-level packet taps: secondary consumers (nested carriers)
// subscribe once and receive inbound DATAGRAM payloads of every generation;
// channels close on loop teardown.
package transportwarp

import (
	"context"
	"testing"
	"time"
)

func TestSubscribePacketsReceivesInboundCapsules(t *testing.T) {
	h := newSupHarness(t)
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = time.Hour
	})

	ch, cancel := sup.SubscribePackets()
	t.Cleanup(cancel)

	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "connected", func() bool {
		st := sup.Snapshot()
		return st.State == StateConnected && st.RouteHeld
	})

	// After connect the fixture is silent (health probes disabled in this
	// scenario): push one datagram out; the fake edge echoes it back, so
	// the tap MUST observe the reply frame.
	if err := sup.WritePacket([]byte("tap-ping")); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	done := make(chan []byte, 1)
	go func() {
		for pkt := range ch {
			if len(pkt) > 0 {
				done <- pkt
				return
			}
		}
		close(done)
	}()
	select {
	case pkt := <-done:
		if len(pkt) != len("tap-ping") {
			t.Fatalf("tap frame = %d bytes, want echoed payload", len(pkt))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no capsule reached the supervisor tap")
	}

	sup.Stop()

	// Loop teardown closes all remaining subscriber channels.
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("tap channel must be closed after Stop")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tap channel was never closed")
	}
}
