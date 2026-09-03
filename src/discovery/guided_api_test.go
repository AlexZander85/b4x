package discovery

import (
	"testing"
	"time"
)

func TestGuidedSnapshotDefaultsAndImmutableDomains(t *testing.T) {
	now := time.Unix(24000, 0)
	p, _ := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Minute), now)
	req := DiscoveryRequest{Domains: []string{"a"}, Options: GuidedDiscoveryOptions{Selection: SelectionExplicit, UseHints: true}, RequestedAt: now}
	s, err := BuildDiscoverySnapshot(req, p, now)
	if err != nil || len(s.Domains) != 1 {
		t.Fatal(err)
	}
	req.Domains[0] = "changed"
	if s.Domains[0] != "a" {
		t.Fatal("snapshot aliases request")
	}
}
