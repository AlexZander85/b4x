package monitor

import (
	"testing"
	"time"
)

func TestDDIAndDiscoveryRequireFreshAuthoritativeInputs(t *testing.T) {
	now := time.Unix(7000, 0)
	scope := testScope()
	ddi := DDIProfileRef{ProfileID: "ddi", Scope: scope, CreatedAt: now, ExpiresAt: now.Add(time.Minute), NetworkContextID: scope.NetworkContextID, ConfigGeneration: scope.ConfigGeneration, CompatibilityHash: "h", AuthoritativeRunID: "abd"}
	req := GuidedDiscoveryRequest{RequestID: "d", Scope: scope, AuthoritativeABDRunID: "abd", DDI: ddi, MandatoryBaselines: []string{"direct"}, CompatibilityHash: "h", RequestedAt: now}
	if _, err := BuildGuidedDiscovery(now, req); err != nil {
		t.Fatal(err)
	}
	req.DDI.ExpiresAt = now.Add(-time.Second)
	if _, err := BuildGuidedDiscovery(now, req); err == nil {
		t.Fatal("stale DDI accepted")
	}
}

func TestRecommendationRequiresIPPathEvidence(t *testing.T) {
	now := time.Unix(7000, 0)
	scope := testScope()
	ddi := DDIProfileRef{ProfileID: "ddi", Scope: scope, NetworkContextID: scope.NetworkContextID, ConfigGeneration: scope.ConfigGeneration, CompatibilityHash: "h", AuthoritativeRunID: "abd"}
	if _, err := BuildTransportRecommendation(now, scope, ddi, "cand", "no path", nil); err == nil {
		t.Fatal("recommendation without path evidence accepted")
	}
	r, err := BuildTransportRecommendation(now, scope, ddi, "cand", "path", []PathEvidence{{EvidenceID: "e", IPHash: "ip", PathKind: "warp", ObservedAt: now, Success: true}})
	if err != nil || !r.Valid() {
		t.Fatalf("valid path rejected: %+v %v", r, err)
	}
}
