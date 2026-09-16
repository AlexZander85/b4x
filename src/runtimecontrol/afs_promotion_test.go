package runtimecontrol

import (
	"strings"
	"testing"
	"time"
)

func validSynthesizedPromotionProof(now time.Time) SynthesizedPromotionProof {
	return SynthesizedPromotionProof{
		CandidateID:                   "candidate-a",
		ServiceProfileID:              "service-a",
		ComponentID:                   "tls",
		SourceClientRole:              "forwarded",
		CandidateConfigGeneration:     7,
		CurrentConfigGeneration:       7,
		ActionAuthorizationID:         "auth-a",
		AuthorizationConfigGeneration: 7,
		AuthorizationValidUntil:       now.Add(time.Minute),
		TargetEvidenceRefs:            []string{"target-e1"},
		SameServiceControlRefs:        []string{"same-control-e1"},
		UnrelatedControlRefs:          []string{"unrelated-control-e1"},
		RollbackReady:                 true,
		CleanupReady:                  true,
		StableObservationReady:        true,
		CheckedAt:                     now,
		ValidUntil:                    now.Add(time.Minute),
	}
}

func validSynthesizedCanary() CanarySpec {
	return CanarySpec{
		ClientGroup:    "ip:192.0.2.10",
		SetID:          "service-a",
		Protocol:       "tcp",
		NewFlowPercent: 10,
		Duration:       30 * time.Second,
		MinSamples:     2,
		Stop: CanaryStopConditions{
			MaxFailures: 1,
		},
	}
}

func TestSynthesizedPromotionProofAcceptsExistingCanaryPath(t *testing.T) {
	now := time.Unix(25000, 0)
	proof := validSynthesizedPromotionProof(now)
	canary := validSynthesizedCanary()
	if err := proof.validatePrepare(now, canary); err != nil {
		t.Fatalf("prepare proof rejected: %v", err)
	}
	outcome := CanaryOutcome{Passed: true, Samples: 3, StartedAt: now, CompletedAt: now.Add(time.Second)}
	if err := proof.validatePromote(now.Add(time.Second), canary, outcome, true); err != nil {
		t.Fatalf("promotion proof rejected: %v", err)
	}
}

func TestSynthesizedPromotionProofRejectsMissingSafetyEvidence(t *testing.T) {
	now := time.Unix(26000, 0)
	tests := []struct {
		name string
		want string
		mut  func(*SynthesizedPromotionProof)
	}{
		{"authorization", "ActionAuthorization", func(p *SynthesizedPromotionProof) { p.ActionAuthorizationID = "" }},
		{"generation", "generation", func(p *SynthesizedPromotionProof) { p.CurrentConfigGeneration++ }},
		{"same-service-control", "control", func(p *SynthesizedPromotionProof) { p.SameServiceControlRefs = nil }},
		{"unrelated-control", "control", func(p *SynthesizedPromotionProof) { p.UnrelatedControlRefs = nil }},
		{"rollback", "rollback", func(p *SynthesizedPromotionProof) { p.RollbackReady = false }},
		{"cleanup", "cleanup", func(p *SynthesizedPromotionProof) { p.CleanupReady = false }},
		{"stability", "stable observation", func(p *SynthesizedPromotionProof) { p.StableObservationReady = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof := validSynthesizedPromotionProof(now)
			tc.mut(&proof)
			err := proof.validatePrepare(now, validSynthesizedCanary())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestSynthesizedPromotionProofRouterOriginStillNeedsForwardedCanary(t *testing.T) {
	now := time.Unix(27000, 0)
	proof := validSynthesizedPromotionProof(now)
	proof.SourceClientRole = "router-origin"
	canary := validSynthesizedCanary()
	failed := CanaryOutcome{Passed: false, Samples: 3, StartedAt: now, CompletedAt: now.Add(time.Second)}
	if err := proof.validatePromote(now.Add(time.Second), canary, failed, true); err == nil || !strings.Contains(err.Error(), "forwarded-client") {
		t.Fatalf("router-origin winner promoted without forwarded proof: %v", err)
	}
}

func TestSynthesizedPromotionProofRequiresRealRollbackState(t *testing.T) {
	now := time.Unix(28000, 0)
	proof := validSynthesizedPromotionProof(now)
	outcome := CanaryOutcome{Passed: true, Samples: 3, StartedAt: now, CompletedAt: now.Add(time.Second)}
	if err := proof.validatePromote(now.Add(time.Second), validSynthesizedCanary(), outcome, false); err == nil || !strings.Contains(err.Error(), "no active generation") {
		t.Fatalf("promotion accepted without rollback state: %v", err)
	}
}
