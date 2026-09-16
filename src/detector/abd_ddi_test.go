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

func TestDDIPriorProjectsBehavioralConstraintsWithExclusionPrecedence(t *testing.T) {
	now := time.Unix(18100, 0)
	envelope := validEnvelope(now)
	scope := envelope.Scope
	features := []BehaviorFeature{
		{FeatureID: "support-split", Confidence: 1, Supports: []StrategyOperatorFamily{OperatorTCPSplit}, EvidenceRefs: []string{"support-ref"}},
		{FeatureID: "exclude-split", Confidence: 1, Excludes: []StrategyOperatorFamily{OperatorTCPSplit}, EvidenceRefs: []string{"exclude-ref"}},
		{FeatureID: "penalize-record", Confidence: 1, Penalizes: []StrategyOperatorFamily{OperatorTLSRecordSplit}, EvidenceRefs: []string{"penalty-ref"}},
	}
	attempts := []BehaviorAttemptSummary{{
		ProbeID:           "behavioral-1",
		Attempt:           1,
		OperatorFamily:    OperatorTCPSplit,
		ReferenceBaseline: BehaviorOutcomeOK,
		TargetBaseline:    BehaviorOutcomeFail,
		ReferenceMutated:  BehaviorOutcomeOK,
		TargetMutated:     BehaviorOutcomeOK,
		Interpretation:    "mutation-bypass-signal",
		Conclusive:        true,
		ObservedAt:        now,
		EvidenceRefs:      []string{"r1", "r2", "r3", "r4"},
	}}
	evidence := NewBehavioralFingerprintEvidence(scope, "afs-panel-v1", features, attempts, 1, 0, now.Add(time.Minute), now)
	profile, err := AttachBehavioralEvidence(envelope.Profile, evidence, nil, now)
	if err != nil {
		t.Fatalf("attach behavioral evidence: %v", err)
	}
	envelope.Profile = profile

	prior, err := BuildDiscoverySearchPrior(GuidedPlannerInput{
		Envelope:          envelope,
		CurrentBaseline:   []string{"direct"},
		CandidateCoverage: []CandidateCoverageVector{{TargetID: "candidate", Covered: true}},
	}, now)
	if err != nil {
		t.Fatalf("build prior: %v", err)
	}
	if prior.BehavioralEvidenceID != evidence.EvidenceID {
		t.Fatalf("behavioral evidence identity lost: got %q want %q", prior.BehavioralEvidenceID, evidence.EvidenceID)
	}
	if len(prior.SupportedOperators) != 0 {
		t.Fatalf("excluded operator leaked into supported list: %+v", prior.SupportedOperators)
	}
	if len(prior.ExcludedOperators) != 1 || prior.ExcludedOperators[0] != OperatorTCPSplit {
		t.Fatalf("excluded operators=%+v, want tcp_split", prior.ExcludedOperators)
	}
	if len(prior.PenalizedOperators) != 1 || prior.PenalizedOperators[0] != OperatorTLSRecordSplit {
		t.Fatalf("penalized operators=%+v, want tls_record_split", prior.PenalizedOperators)
	}
	if !prior.Valid() {
		t.Fatalf("behavioral prior invalid: %+v", prior)
	}
}
