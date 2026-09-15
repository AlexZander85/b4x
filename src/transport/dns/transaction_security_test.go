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

func TestTransactionRejectsSinglePassProfileEvenWhenCallerSetsAllGates(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	now := time.Now()
	profile := &DNSPathProfile{
		ProfileID: "dnsprof-single-pass", Status: ProfileStatusReady,
		NetworkContextID: "wan-1", ConfigGeneration: 7, RuntimeEpoch: "epoch-1",
		QuerySuiteVersion: "adns-suite-v1",
		Primary: primary.id, Fallbacks: []DNSPathID{fallback.id},
		CandidateOutcomes: []DNSPathProbeOutcome{
			{PathID: primary.id, QuerySuiteID: "A", Class: OutcomePassCorrect},
			{PathID: fallback.id, QuerySuiteID: "A", Class: OutcomePassCorrect},
		},
		CreatedAt: now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := m.AdoptProfile(profile); err != nil {
		t.Fatal(err)
	}
	binding, err := m.NewBinding("lan", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tx := &Transaction{
		Profile: profile, Candidate: binding, Gate: externallyGreenGate(),
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(context.Background(), m); err == nil {
		t.Fatal("single PASS outcome must not authorize promotion")
	}
	if !strings.Contains(tx.Reason, "promotion evidence invalid") {
		t.Fatalf("unexpected rejection reason: %q", tx.Reason)
	}
	if m.ActiveBinding() != nil {
		t.Fatal("rejected promotion must not install a binding")
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

func TestTransactionRejectsContradictoryCanonicalEvidence(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	for i := range profile.CandidateOutcomes {
		if profile.CandidateOutcomes[i].PathID.Hash() == primary.id.Hash() && profile.CandidateOutcomes[i].QuerySuiteID == "CONTROL_SAME" {
			profile.CandidateOutcomes[i].Class = OutcomeAnswerConflict
			break
		}
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := m.AdoptProfile(profile); err != nil {
		t.Fatal(err)
	}
	binding, _ := m.NewBinding("lan", time.Hour)
	tx := &Transaction{
		Profile: profile, Candidate: binding, Gate: externallyGreenGate(),
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(context.Background(), m); err == nil {
		t.Fatal("contradictory canonical evidence must block promotion")
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
