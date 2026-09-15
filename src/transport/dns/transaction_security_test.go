package dnspath

import (
	"context"
	"strings"
	"testing"
	"time"
)

func prepareTransactionFixture(t *testing.T) (*Manager, *stubProvider, *stubProvider) {
	t.Helper()
	m, primary, fallback := managerFixture(t)
	ctx := context.Background()
	if err := m.PreparePath(ctx, primary, false); err != nil {
		t.Fatal(err)
	}
	if err := m.PreparePath(ctx, fallback, false); err != nil {
		t.Fatal(err)
	}
	m.MarkPathHealth(primary.id, DNSPathHealth{State: CapReady})
	m.MarkPathHealth(fallback.id, DNSPathHealth{State: CapReady})
	return m, primary, fallback
}

func externallyGreenGate() PromotionGate {
	return PromotionGate{
		FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
		SameServiceControls: true, UnrelatedControls: true,
		AndroidCanary: true, CacheReady: true, RollbackReady: true,
		NoBlockingHardGate: true, MetricsParity: true,
	}
}

func TestAdoptionRejectsSinglePassProfileEvenWhenCallerWouldSetAllGates(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	now := time.Now()
	profile := &DNSPathProfile{
		ProfileID: "dnsprof-single-pass", Status: ProfileStatusReady,
		NetworkContextID: "wan-1", ConfigGeneration: 7, RuntimeEpoch: "epoch-1",
		QuerySuiteVersion: "adns-suite-v1",
		Primary: primary.id, Fallbacks: []DNSPathID{fallback.id},
		CandidateOutcomes: []DNSPathProbeOutcome{
			{PathID: primary.id, QuerySuiteID: "A", Attempt: 1, Class: OutcomePassCorrect},
			{PathID: fallback.id, QuerySuiteID: "A", Attempt: 1, Class: OutcomePassCorrect},
		},
		CreatedAt: now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := m.AdoptProfile(profile); err == nil {
		t.Fatal("single PASS outcome must be rejected before it can become staged promotion state")
	}
	if m.Profile() != nil || m.ActiveBinding() != nil {
		t.Fatal("rejected weak profile must not change manager state")
	}
}

func TestTransactionRejectsBindingPrimaryDifferentFromAdoptedProfile(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	binding, err := m.NewBinding("lan", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	binding.Primary = fallback.id
	tx := &Transaction{
		Profile: profile, Candidate: binding, Gate: externallyGreenGate(),
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(context.Background(), m); err == nil {
		t.Fatal("binding/profile primary mismatch must abort")
	}
	if !strings.Contains(tx.Reason, "binding primary differs") {
		t.Fatalf("unexpected rejection reason: %q", tx.Reason)
	}
}

func TestAdoptionRejectsContradictoryCanonicalEvidence(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	original := m.Profile()
	for i := range profile.CandidateOutcomes {
		if profile.CandidateOutcomes[i].PathID.Hash() == primary.id.Hash() && profile.CandidateOutcomes[i].QuerySuiteID == "CONTROL_SAME" {
			profile.CandidateOutcomes[i].Class = OutcomeAnswerConflict
			break
		}
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := m.AdoptProfile(profile); err == nil {
		t.Fatal("contradictory canonical evidence must be rejected at adoption")
	}
	// Manager stores immutable profile semantics; a caller must not mutate an
	// adopted profile in production. This assertion only checks that adoption
	// itself did not install a second candidate state.
	if m.Profile() == nil || m.Profile().ProfileID != original.ProfileID {
		t.Fatal("failed re-adoption must retain the previously staged profile identity")
	}
}

func TestTransactionCallerCannotSpoofCanarySuccess(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	binding, _ := m.NewBinding("lan", time.Hour)
	tx := &Transaction{
		Profile: profile, Candidate: binding, Gate: externallyGreenGate(),
		Canary: nil,
	}
	if err := tx.Run(context.Background(), m); err == nil {
		t.Fatal("AndroidCanary=true without executing a canary must not authorize promotion")
	}
	if !strings.Contains(tx.Reason, "source-scoped Android/LAN canary") {
		t.Fatalf("unexpected rejection reason: %q", tx.Reason)
	}
}

func TestTransactionRejectsUnpreparedFallback(t *testing.T) {
	m, primary, fallback := managerFixture(t)
	if err := m.PreparePath(context.Background(), primary, false); err != nil {
		t.Fatal(err)
	}
	m.MarkPathHealth(primary.id, DNSPathHealth{State: CapReady})
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	binding, _ := m.NewBinding("lan", time.Hour)
	tx := &Transaction{
		Profile: profile, Candidate: binding, Gate: externallyGreenGate(),
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(context.Background(), m); err == nil {
		t.Fatal("unprepared fallback must block promotion")
	}
	if !strings.Contains(tx.Reason, "not registered") && !strings.Contains(tx.Reason, "not prepared") {
		t.Fatalf("unexpected rejection reason: %q", tx.Reason)
	}
}
