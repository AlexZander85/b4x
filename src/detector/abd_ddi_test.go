package detector

import (
	"testing"
	"time"
)

func validEnvelope(now time.Time) NetworkDiagnosticProfileEnvelope {
	scope := monitorScopeForDetector()
	p, _, _ := CompileBlockingProfile(profileGraph(), MonitorAssessmentRef{AssessmentID: "a", RequestID: "r", Scope: scope, ConfigGeneration: 1}, "blocked", true, true, []string{"e"}, now)
	return NetworkDiagnosticProfileEnvelope{EnvelopeID: "env", Scope: scope, Profile: p, CreatedAt: now, ExpiresAt: now.Add(time.Minute), CompatibilityHash: "h"}
}
func TestDDIPriorRequiresFreshEnvelopeAndBaseline(t *testing.T) {
	now := time.Unix(18000, 0)
	in := GuidedPlannerInput{Envelope: validEnvelope(now), CurrentBaseline: []string{"direct"}, CandidateCoverage: []CandidateCoverageVector{{TargetID: "c", Covered: true}}}
	p, err := BuildDiscoverySearchPrior(in, now)
	if err != nil || !p.Valid() {
		t.Fatalf("prior rejected: %+v %v", p, err)
	}
	in.CurrentBaseline = nil
	if _, err := BuildDiscoverySearchPrior(in, now); err == nil {
		t.Fatal("baseline-less prior accepted")
	}
}
func TestDDIPriorCannotDropExcludedDenominator(t *testing.T) {
	now := time.Unix(18000, 0)
	in := GuidedPlannerInput{Envelope: validEnvelope(now), CurrentBaseline: []string{"direct"}, CandidateCoverage: []CandidateCoverageVector{{TargetID: "ok", Covered: true}, {TargetID: "excluded", Excluded: true, ExclusionReason: "scope"}}}
	p, err := BuildDiscoverySearchPrior(in, now)
	if err != nil || p.CoverageDenominator != 2 || len(p.ExcludedTargets) != 1 {
		t.Fatalf("coverage denominator lost: %+v %v", p, err)
	}
	merged := p.MergeBaseline([]string{"fallback"})
	if merged[0] != "direct" {
		t.Fatal("baseline not first")
	}
}
