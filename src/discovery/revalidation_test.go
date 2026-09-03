package discovery

import (
	"testing"
	"time"
)

func TestRevalidationBoundedAndConflictAware(t *testing.T) {
	now := time.Unix(23000, 0)
	p, _ := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Minute), now)
	r, err := BuildRevalidationPlan(p, now)
	if err != nil || len(r.Probes) != 2 || !r.Probes[0].NoSideEffect {
		t.Fatal(err)
	}
	r = ResolveRevalidation(r, "a", "b", now)
	if r.Status != RevalidationConflict {
		t.Fatal(r)
	}
}
