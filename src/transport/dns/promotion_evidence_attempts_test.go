package dnspath

import "testing"

func TestPromotionEvidenceRequiresRepeatedDetectorAttempts(t *testing.T) {
	path := DNSPathID{Family: DNSPathTCP, ResolverID: "r1", EndpointID: "e1", IPFamily: "ipv4"}
	profile := &DNSPathProfile{Primary: path}
	for _, caseID := range canonicalPromotionCases {
		profile.CandidateOutcomes = append(profile.CandidateOutcomes, DNSPathProbeOutcome{
			PathID: path, QuerySuiteID: caseID, Attempt: 1, Class: OutcomePassCorrect,
		})
	}
	if err := ValidatePromotionEvidence(profile); err == nil {
		t.Fatal("one detector attempt per canonical case must not authorize promotion")
	}
	for _, caseID := range canonicalPromotionCases {
		profile.CandidateOutcomes = append(profile.CandidateOutcomes, DNSPathProbeOutcome{
			PathID: path, QuerySuiteID: caseID, Attempt: 2, Class: OutcomePassDifferentButValid,
		})
	}
	if err := ValidatePromotionEvidence(profile); err != nil {
		t.Fatalf("two corroborated detector attempts should satisfy evidence floor: %v", err)
	}
}

func TestPromotionEvidenceRejectsAnyCanonicalContradiction(t *testing.T) {
	path := DNSPathID{Family: DNSPathTCP, ResolverID: "r1", EndpointID: "e1", IPFamily: "ipv4"}
	profile := &DNSPathProfile{Primary: path}
	for _, caseID := range canonicalPromotionCases {
		for attempt := uint16(1); attempt <= 2; attempt++ {
			class := OutcomePassCorrect
			if caseID == "CONTROL_UNRELATED" && attempt == 2 {
				class = OutcomeAnswerConflict
			}
			profile.CandidateOutcomes = append(profile.CandidateOutcomes, DNSPathProbeOutcome{
				PathID: path, QuerySuiteID: caseID, Attempt: attempt, Class: class,
			})
		}
	}
	if err := ValidatePromotionEvidence(profile); err == nil {
		t.Fatal("a contradictory canonical receipt must block promotion")
	}
}
