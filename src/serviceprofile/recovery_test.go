package serviceprofile

import "testing"

func TestValidateRecoveryRequiresCooldownForActiveMode(t *testing.T) {
	b := RecoveryBinding{
		ID: "r1", ComponentID: "c", ClientScope: "ls::451058_net::_vpn::", ConfigGeneration: "g1",
		Mode: RecoveryAutoCanary, RollbackTarget: "rollback",
		TTLSeconds: 300, MaxAttempts: 2,
	}
	if err := ValidateRecovery(b); err == nil {
		t.Fatal("auto-canary without cooldown must fail (SP-22)")
	}
	b.CooldownSeconds = 120
	if err := ValidateRecovery(b); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryLeaseRequiresCooldownBounds(t *testing.T) {
	l := RecoveryLease{
		ID: "lease", BindingID: "k1", ClientScope: "ls::", ComponentID: "cub",
		ConfigGeneration: 7, TTLSeconds: 300, MaxAttempts: 2,
	}
	if l.Valid() {
		t.Fatal("lease without cooldown must be invalid (SP-22)")
	}
	l.CooldownSeconds = 120
	if !l.Valid() {
		t.Fatal("lease with cooldown bounds must be valid")
	}
}

func TestRecoveryPromotionInvalidationForbidsUse(t *testing.T) {
	p := RecoveryPromotion{
		Mode:                RecoveryAutoCanary,
		EvidenceRefs:        []string{"ft-r", "ft-v"},
		FieldTests:          []string{"SPF-1", "SPF-2"},
		FalsePositiveBudget: 1,
		Validated:           true,
	}
	if !p.Ready() {
		t.Fatal("populated promotion must be ready")
	}
	// SP-23: material profile/capability/network change invalidates promotion.
	p.Invalidate("config generation changed")
	if p.Ready() {
		t.Fatal("invalidated promotion must not be ready")
	}
	if !p.Invalidated || p.Validated || p.InvalidReason == "" {
		t.Fatalf("promotion must record invalidation, got %+v", p)
	}
	// Invalidate with empty reason is ignored (value receiver copies; use pointer).
	child := p
	child.Invalidate("")
	if !child.Invalidated || child.InvalidReason == "" {
		t.Fatal("empty-reason invalidation must not reset the promotion")
	}
}
