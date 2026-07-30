package warp

import (
	"testing"
	"time"
)

func TestHealthTrackerBoundsSelfHeal(t *testing.T) {
	now := time.Unix(31000, 0)
	h := HealthTracker{}
	h.Observe(false, false, now)
	h.Observe(false, false, now.Add(time.Second))
	h.Observe(false, false, now.Add(2*time.Second))
	if h.State != HealthCooldown || h.CanRetry(now.Add(time.Second)) {
		t.Fatal("failure cooldown missing")
	}
	if !h.CanRetry(now.Add(2 * time.Minute)) {
		t.Fatal("cooldown did not expire")
	}
}
