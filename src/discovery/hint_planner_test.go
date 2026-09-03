package discovery

import (
	"github.com/daniellavrushin/b4/detector"
	"testing"
)

func TestHintPlannerKeepsBaselineAndFallback(t *testing.T) {
	p := CompileHintPlan(detector.DiscoverySearchPrior{}, []string{"direct"}, []SearchHint{{Candidate: "fake-sni", Action: HintBoost, Weight: 10, Provenance: "abd"}, {Candidate: "", Action: HintBoost}})
	if !p.Valid() || p.Ordered[0] != "direct" || !p.ExhaustiveFallback {
		t.Fatalf("unsafe plan: %+v", p)
	}
}
