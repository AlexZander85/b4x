package discovery

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

func synthesizedWinnerTestScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "client-a", Role: "forwarded"},
		ServiceProfileID: "service-a",
		ComponentID:      "tls",
		TargetRole:       "target",
		IPFamily:         "ipv4",
		NetworkContextID: "network-a",
		ConfigGeneration: 7,
	}
}

func synthesizedWinnerTestKey(scope monitor.MonitorScopeKey) SynthesizedWinnerCompatibilityKey {
	return SynthesizedWinnerCompatibilityKey{
		Scope:             scope,
		WANFingerprint:    "wan-hash-a",
		ResolverContextID: "resolver-a",
		TLSContextID:      "tls-a",
		GrammarVersion:    SynthesisGrammarV1,
		CapabilityGenerations: map[string]uint64{
			"capture": 3,
			"gso":     4,
			"ppe":     5,
		},
	}
}

func synthesizedWinnerTestCandidate(t *testing.T, scope monitor.MonitorScopeKey, jitter string, now time.Time) SynthesizedCandidatePlan {
	t.Helper()
	req := SynthesisRequest{
		Scope:                 scope,
		ConfigGeneration:      scope.ConfigGeneration,
		BlockingProfileID:     "bp-a",
		BehavioralEvidenceID:  "be-a",
		AllowedGrammarVersion: SynthesisGrammarV1,
	}
	candidate, err := newSynthesizedCandidate(
		req,
		0,
		nil,
		CandidateTrigger{Phase: "complete-reassembled-clienthello", Marker: "host-start"},
		[]CandidateOperation{{Family: detector.OperatorPerFlowJitter, Params: map[string]string{"jitter_ms": jitter}}},
		action.RepresentationNormalTCP,
		[]string{"current-action-authorization"},
		CandidateCost{Actions: 1, EstimatedPackets: 1, Amplification: 1},
		CandidateRisk{Tier: "endpoint-safe", AutomaticOK: true},
		[]string{"test-seed"},
		now,
	)
	if err != nil {
		t.Fatalf("candidate: %v", err)
	}
	return candidate
}

func TestSynthesizedWinnerStoreBoundsPerScopeAndExactContext(t *testing.T) {
	now := time.Unix(20000, 0)
	scope := synthesizedWinnerTestScope()
	key := synthesizedWinnerTestKey(scope)
	history := &DiscoveryHistory{}
	jitters := []string{"0", "1", "2", "4", "8"}
	for i, jitter := range jitters {
		promoted := now.Add(time.Duration(i) * time.Minute)
		record := SynthesizedWinnerRecord{
			Compatibility: key,
			Candidate:     synthesizedWinnerTestCandidate(t, scope, jitter, promoted),
			EvidenceRefs:  []string{"be-a"},
			PromotedAt:    promoted,
			ExpiresAt:     now.Add(24 * time.Hour),
			RevalidateAt:  now.Add(time.Hour),
		}
		if err := history.AddSynthesizedWinner(record, now); err != nil {
			t.Fatalf("add winner %d: %v", i, err)
		}
	}
	if got := len(history.SynthesizedWinners); got != maxSynthesizedWinnersPerScope {
		t.Fatalf("per-scope bound = %d, want %d", got, maxSynthesizedWinnersPerScope)
	}
	compatible := history.CompatibleSynthesizedWinners(key, now)
	if len(compatible) != maxSynthesizedWinnersPerScope {
		t.Fatalf("compatible winners = %d", len(compatible))
	}
	if compatible[0].Candidate.Operations[0].Params["jitter_ms"] != "8" {
		t.Fatal("newest winner is not first")
	}

	drifted := key
	drifted.WANFingerprint = "wan-hash-b"
	if got := history.CompatibleSynthesizedWinners(drifted, now); len(got) != 0 {
		t.Fatalf("WAN drift leaked %d winner(s)", len(got))
	}
	drifted = key
	drifted.CapabilityGenerations = map[string]uint64{"capture": 3, "gso": 99, "ppe": 5}
	if got := history.CompatibleSynthesizedWinners(drifted, now); len(got) != 0 {
		t.Fatalf("capability generation drift leaked %d winner(s)", len(got))
	}
}

func TestSynthesizedWinnerQuarantinePreventsReuseButKeepsAuditRecord(t *testing.T) {
	now := time.Unix(21000, 0)
	scope := synthesizedWinnerTestScope()
	key := synthesizedWinnerTestKey(scope)
	history := &DiscoveryHistory{}
	candidate := synthesizedWinnerTestCandidate(t, scope, "2", now)
	record := SynthesizedWinnerRecord{
		Compatibility: key,
		Candidate:     candidate,
		EvidenceRefs:  []string{"be-a"},
		PromotedAt:    now,
		ExpiresAt:     now.Add(24 * time.Hour),
		RevalidateAt:  now.Add(30 * time.Minute),
	}
	if err := history.AddSynthesizedWinner(record, now); err != nil {
		t.Fatalf("add winner: %v", err)
	}
	if err := history.QuarantineSynthesizedWinner(key, candidate.CandidateID, "rollback: collateral regression", now.Add(time.Minute)); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if got := history.CompatibleSynthesizedWinners(key, now.Add(2*time.Minute)); len(got) != 0 {
		t.Fatalf("quarantined winner leaked into reuse set: %d", len(got))
	}
	if len(history.SynthesizedWinners) != 1 || history.SynthesizedWinners[0].QuarantinedAt.IsZero() || history.SynthesizedWinners[0].QuarantineReason == "" {
		t.Fatal("quarantine audit record was not retained")
	}
	if !record.NeedsRevalidation(now.Add(time.Hour)) {
		t.Fatal("revalidation deadline not recognized")
	}
}
