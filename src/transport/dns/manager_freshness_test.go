package dnspath

import (
	"context"
	"testing"
	"time"
)

func TestNewBindingCannotOutliveProfile(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	binding, err := m.NewBinding("lan", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if binding.ValidUntil.After(profile.ValidUntil) {
		t.Fatalf("binding expiry %s exceeds profile expiry %s", binding.ValidUntil, profile.ValidUntil)
	}
}

func TestResolveRejectsExpiredActiveBinding(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	binding, err := m.NewBinding("lan", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	binding.ValidUntil = time.Now().Add(-time.Second)
	m.mu.Lock()
	m.active = binding
	m.profile = profile
	m.mu.Unlock()
	if _, err := m.Resolve(context.Background(), DNSQuery{Name: "example.com", QType: 1, TxID: 1}); err == nil {
		t.Fatal("expired active binding must not serve production DNS")
	}
}

func TestTransactionRechecksGenerationAfterCanary(t *testing.T) {
	m, primary, fallback := prepareTransactionFixture(t)
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	binding, err := m.NewBinding("lan", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tx := &Transaction{
		Profile: profile, Candidate: binding,
		Gate: PromotionGate{NoBlockingHardGate: true, MetricsParity: true},
		Canary: func(context.Context, *DNSPathBinding) error {
			m.InvalidateOnContextChange(8, "wan-2")
			return nil
		},
	}
	if err := tx.Run(context.Background(), m); err == nil {
		t.Fatal("generation/context change during canary must abort promotion")
	}
	if m.ActiveBinding() != nil {
		t.Fatal("stale candidate must not become active")
	}
}
