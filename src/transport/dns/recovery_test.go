package dnspath

import (
	"context"
	"testing"
	"time"
)

func TestFastFailoverOnlyToReadyFallback(t *testing.T) {
	m, primary, fallback := managerFixture(t)
	ctx := context.Background()
	m.PreparePath(ctx, primary, false)
	m.PreparePath(ctx, fallback, false)
	m.MarkPathHealth(primary.id, DNSPathHealth{State: CapReady})
	adoptTestProfile(t, m, primary.id, fallback.id)
	binding, _ := m.NewBinding("lan", time.Hour)
	tx := &Transaction{
		Profile: m.Profile(), Candidate: binding,
		Gate: PromotionGate{
			FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
			SameServiceControls: true, UnrelatedControls: true,
			NoBlockingHardGate: true, MetricsParity: true,
		},
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(ctx, m); err != nil {
		t.Fatal(err)
	}
	pol := DefaultAdaptivePolicy()
	fc := NewFailoverController(pol)
	// fallback not ready → no blind switch
	if d := fc.OnPrimaryFailure(m, time.Now()); d == DecisionFastFailover {
		t.Fatal("fast failover toward unready fallback is a blind switch")
	}
	m.MarkPathHealth(fallback.id, DNSPathHealth{State: CapReady})
	if d := fc.OnPrimaryFailure(m, time.Now()); d != DecisionFastFailover {
		t.Fatalf("ready fallback must allow fast failover, got %s", d)
	}
	// cooldown after switch
	fc.NoteSwitch(time.Now())
	if d := fc.OnPrimaryFailure(m, time.Now().Add(time.Minute)); d != DecisionCooldownWait {
		t.Fatalf("cooldown must suppress immediate re-switch, got %s", d)
	}
}

func TestDeepDiagnosisWhenNoFallback(t *testing.T) {
	m, _, _ := managerFixture(t)
	pol := DefaultAdaptivePolicy()
	fc := NewFailoverController(pol)
	if d := fc.OnPrimaryFailure(m, time.Now()); d != DecisionDeepDiagnosis {
		t.Fatalf("no binding must schedule deep diagnosis, got %s", d)
	}
	fc.NoteFailedSearch(time.Now())
	if d := fc.OnPrimaryFailure(m, time.Now().Add(time.Minute)); d != DecisionCooldownWait {
		t.Fatalf("failed-search cooldown must hold, got %s", d)
	}
}

func TestRecoveryHysteresis(t *testing.T) {
	pol := DefaultAdaptivePolicy()
	pol.RecoveryHysteresis = 30 * time.Minute
	fc := NewFailoverController(pol)
	simpler := DNSPathID{Family: DNSPathUDP, ResolverID: "r-s", IPFamily: "ipv4"}
	current := DNSPathID{Family: DNSPathDNSCrypt, ResolverID: "r-c", IPFamily: "ipv4"}
	now := time.Now()
	// not enough proofs
	if d := fc.OnSimplerPathProven(simpler, current, now); d != DecisionNone {
		t.Fatal("single proof must not trigger recovery")
	}
	fc.OnSimplerPathProven(simpler, current, now.Add(time.Minute))
	// enough proofs but hysteresis not elapsed
	if d := fc.OnSimplerPathProven(simpler, current, now.Add(2*time.Minute)); d != DecisionNone {
		t.Fatal("hysteresis must prevent flapping")
	}
	// hysteresis elapsed with continued proofs
	if d := fc.OnSimplerPathProven(simpler, current, now.Add(31*time.Minute)); d != DecisionRecoveryCanary {
		t.Fatalf("proven simpler path after hysteresis must recommend recovery canary, got %s", d)
	}
	// never recover toward a more complex path
	if d := fc.OnSimplerPathProven(current, simpler, now); d != DecisionNone {
		t.Fatal("recovery must prefer minimum complexity")
	}
}
