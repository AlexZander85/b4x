package discovery

import (
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

// FB-05 (b4x-1z5, #278): CompileHintPlan must apply the detector search
// prior for ordering/ranking only — the current baseline stays dominant
// (ABD-11: "keep current active target evidence dominant over
// stored/passive priors"), prior-preferred targets are ranked first in the
// extension, prior-excluded targets are deferred but stay visible ("excluded
// targets remain visible"), and a prior can never add or remove candidates
// or skip the exhaustive fallback.

func validPriorScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "client-a", Role: "forwarded"},
		ServiceProfileID: "svc-a",
		ComponentID:      "web",
		DomainIdentityID: "example.com",
		TargetRole:       "target",
		NetworkContextID: "wan-a",
		ConfigGeneration: 7,
	}
}

func validPrior() detector.DiscoverySearchPrior {
	return detector.DiscoverySearchPrior{
		Scope:               validPriorScope(),
		ProfileID:           "p-1",
		CoverageDenominator: 3,
		MandatoryBaselines:  []string{"direct"},
	}
}

// helper: index of candidate in Ordered, -1 when absent.
func orderIndex(p GuidedSearchPlan, want string) int {
	for i, c := range p.Ordered {
		if c == want {
			return i
		}
	}
	return -1
}

func TestHintPlanPriorOrdersExtensionAfterBaseline(t *testing.T) {
	prior := validPrior()
	prior.TargetOrder = []string{"tls", "socks"}
	p := CompileHintPlan(prior, []string{"direct"}, []SearchHint{
		{Candidate: "fake", Action: HintBoost, Weight: 10, Provenance: "abd"},
		{Candidate: "socks", Action: HintBoost, Weight: 5, Provenance: "abd"},
		{Candidate: "tls", Action: HintBoost, Weight: 1, Provenance: "abd"},
	})
	if !p.Valid() {
		t.Fatalf("plan invalid: %+v", p)
	}
	// Baseline always first and intact.
	if len(p.Baseline) != 1 || p.Baseline[0] != "direct" {
		t.Fatalf("baseline changed: %v", p.Baseline)
	}
	if p.Ordered[0] != "direct" {
		t.Fatalf("baseline lost leading position: %v", p.Ordered)
	}
	// Prior-preferred targets are ranked before the remaining extension.
	idxTLS, idxSocks, idxFake := orderIndex(p, "tls"), orderIndex(p, "socks"), orderIndex(p, "fake")
	if idxTLS == -1 || idxSocks == -1 || idxFake == -1 {
		t.Fatalf("extension incomplete: %v", p.Ordered)
	}
	if !(idxTLS < idxSocks && idxSocks < idxFake) {
		t.Fatalf("prior order not applied: tls=%d socks=%d fake=%d ordered=%v", idxTLS, idxSocks, idxFake, p.Ordered)
	}
	if !strings.Contains(p.Explanation, "detector prior") {
		t.Fatalf("explanation must record prior application, got %q", p.Explanation)
	}
}

func TestHintPlanPriorDeferredTargetsStayVisible(t *testing.T) {
	prior := validPrior()
	prior.TargetOrder = []string{"tls"}
	prior.ExcludedTargets = []string{"fake"}
	p := CompileHintPlan(prior, []string{"direct"}, []SearchHint{
		{Candidate: "fake", Action: HintBoost, Weight: 10, Provenance: "abd"},
		{Candidate: "socks", Action: HintBoost, Weight: 5, Provenance: "abd"},
		{Candidate: "tls", Action: HintBoost, Weight: 1, Provenance: "abd"},
	})
	if orderIndex(p, "fake") == -1 {
		t.Fatalf("excluded target hidden from plan: %v", p.Ordered)
	}
	if orderIndex(p, "fake") < orderIndex(p, "socks") {
		t.Fatalf("excluded target not deferred: %v", p.Ordered)
	}
}

func TestHintPlanPriorCannotSkipBaseline(t *testing.T) {
	prior := validPrior()
	prior.TargetOrder = []string{"tls", "direct"}
	p := CompileHintPlan(prior, []string{"direct", "dns"}, []SearchHint{
		{Candidate: "tls", Action: HintBoost, Weight: 10, Provenance: "abd"},
	})
	// Baseline remains first, in order, regardless of prior preference.
	if len(p.Ordered) < 2 || p.Ordered[0] != "direct" || p.Ordered[1] != "dns" {
		t.Fatalf("prior reordered baseline: %v", p.Ordered)
	}
	if orderIndex(p, "tls") < 2 {
		t.Fatalf("prior candidate inserted before baseline: %v", p.Ordered)
	}
}

func TestHintPlanPriorDoesNotExpandCandidateSet(t *testing.T) {
	prior := validPrior()
	prior.TargetOrder = []string{"ghost", "tls"}
	p := CompileHintPlan(prior, []string{"direct"}, []SearchHint{
		{Candidate: "tls", Action: HintBoost, Weight: 5, Provenance: "abd"},
	})
	// ghost is not part of baseline or hints: a prior must never invent
	// candidates (ordering/ranking only).
	if orderIndex(p, "ghost") != -1 {
		t.Fatalf("prior invented candidate: %v", p.Ordered)
	}
	if orderIndex(p, "tls") != 1 {
		t.Fatalf("prior-preferred candidate misplaced: %v", p.Ordered)
	}
}
