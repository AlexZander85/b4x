package dnspath

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// TransactionPhase is the transactional switch phase (addendum §76).
type TransactionPhase string

const (
	PhasePrepare  TransactionPhase = "prepare"
	PhaseCanary   TransactionPhase = "canary"
	PhasePromote  TransactionPhase = "promote"
	PhaseRollback TransactionPhase = "rollback"
	PhaseDone     TransactionPhase = "done"
	PhaseAborted  TransactionPhase = "aborted"
)

// PromotionGate is the mandatory promotion checklist (addendum §71).
type PromotionGate struct {
	FreshProfile        bool
	ProviderReady       bool
	CorrectnessSuite    bool
	SameServiceControls bool
	UnrelatedControls   bool
	AndroidCanary       bool
	CacheReady          bool
	RollbackReady       bool
	NoBlockingHardGate  bool
	MetricsParity       bool
}

// Check enforces every promotion requirement; a single successful query is
// never enough (§71, Appendix E).
func (g PromotionGate) Check() error {
	type req struct {
		ok   bool
		name string
	}
	for _, r := range []req{
		{g.FreshProfile, "fresh profile/context/generation"},
		{g.ProviderReady, "provider readiness"},
		{g.CorrectnessSuite, "correctness suite"},
		{g.SameServiceControls, "same-service controls"},
		{g.UnrelatedControls, "unrelated controls"},
		{g.AndroidCanary, "source-scoped Android/LAN canary"},
		{g.CacheReady, "cache migration/partition readiness"},
		{g.RollbackReady, "rollback readiness"},
		{g.NoBlockingHardGate, "blocking hard gate"},
		{g.MetricsParity, "metrics/API/report parity"},
	} {
		if !r.ok {
			return fmt.Errorf("promotion gate failed: %s required", r.name)
		}
	}
	return nil
}

// CanaryFunc runs the source-scoped canary for a candidate binding.
type CanaryFunc func(ctx context.Context, candidate *DNSPathBinding) error

// Transaction is one prepare/canary/promote/rollback cycle.
type Transaction struct {
	Profile   *DNSPathProfile
	Candidate *DNSPathBinding
	LastGood  *DNSPathBinding
	Gate      PromotionGate
	Canary    CanaryFunc

	Phase     TransactionPhase
	Reason    string
	StartedAt time.Time
	EndedAt   time.Time
}

var (
	ErrTransactionAborted = errors.New("dns path transaction aborted")
)

// Run executes the transaction. Evidence-derived gate fields are computed
// here and never trusted from caller-supplied booleans. Any failure before or
// during canary leaves the current binding unchanged; rollback restores
// last-good and preserves the reason (§71/§76/§97).
func (t *Transaction) Run(ctx context.Context, m *Manager) error {
	t.StartedAt = time.Now()
	t.Phase = PhasePrepare
	if m == nil || t.Profile == nil || t.Candidate == nil {
		t.abort("manager, profile and candidate binding required")
		return ErrTransactionAborted
	}
	now := time.Now()
	if err := t.Profile.Valid(now); err != nil {
		t.abort("profile invalid: " + err.Error())
		return ErrTransactionAborted
	}
	if err := validateTransactionProfileAndBinding(m, t.Profile, t.Candidate, now); err != nil {
		t.abort("candidate/profile mismatch: " + err.Error())
		return ErrTransactionAborted
	}
	if err := ValidatePromotionEvidence(t.Profile); err != nil {
		t.abort("promotion evidence invalid: " + err.Error())
		return ErrTransactionAborted
	}
	if err := validateRuntimeProviderReadiness(m, t.Candidate); err != nil {
		t.abort("provider readiness failed: " + err.Error())
		return ErrTransactionAborted
	}

	// These fields are derived exclusively from the checks above. A caller
	// cannot authorize promotion by setting them true on an invalid profile.
	t.Gate.FreshProfile = true
	t.Gate.ProviderReady = true
	t.Gate.CorrectnessSuite = true
	t.Gate.SameServiceControls = true
	t.Gate.UnrelatedControls = true

	// PREPARE: cache partition for the new generation must be ready and
	// isolated from the old one.
	m.cache.ResetPartition(t.Profile.NetworkContextID, t.Profile.ConfigGeneration, t.Candidate.Primary.Hash())
	t.Gate.CacheReady = true
	// Rollback readiness: with a retained last-good we restore it; on the
	// first-ever promotion rollback means reverting to the pre-adaptive
	// behavior (no adaptive binding), which is always available.
	t.Gate.RollbackReady = true

	t.Phase = PhaseCanary
	// A real canary callback is mandatory. Caller-supplied AndroidCanary=true
	// cannot substitute for executing the source-scoped canary.
	t.Gate.AndroidCanary = false
	if t.Canary != nil {
		if err := t.Canary(ctx, t.Candidate); err == nil {
			t.Gate.AndroidCanary = true
		}
	}
	if err := t.Gate.Check(); err != nil {
		t.rollback(m, err.Error())
		return ErrTransactionAborted
	}

	// Recheck generation/epoch immediately before the atomic swap so a WAN or
	// config change during canary cannot promote stale evidence.
	if err := validateTransactionProfileAndBinding(m, t.Profile, t.Candidate, time.Now()); err != nil {
		t.rollback(m, "pre-promote freshness check failed: "+err.Error())
		return ErrTransactionAborted
	}

	t.Phase = PhasePromote
	m.promote(t.Candidate, t.LastGood)
	t.Phase = PhaseDone
	t.EndedAt = time.Now()
	return nil
}

func validateTransactionProfileAndBinding(m *Manager, profile *DNSPathProfile, candidate *DNSPathBinding, now time.Time) error {
	m.mu.RLock()
	generation := m.generation
	epoch := m.epoch
	networkCtx := m.networkCtx
	adopted := m.profile
	m.mu.RUnlock()

	if profile.NetworkContextID != networkCtx || profile.ConfigGeneration != generation || profile.RuntimeEpoch != epoch {
		return errors.New("profile does not match live network context/generation/epoch")
	}
	if adopted == nil || adopted.ProfileID != profile.ProfileID || adopted.ContentHash != profile.ContentHash {
		return errors.New("profile is not the currently adopted immutable profile")
	}
	if candidate.ProfileID != profile.ProfileID {
		return errors.New("binding profile id differs from profile")
	}
	if candidate.Primary.Hash() != profile.Primary.Hash() {
		return errors.New("binding primary differs from profile primary")
	}
	if candidate.ConfigGeneration != profile.ConfigGeneration || candidate.RuntimeEpoch != profile.RuntimeEpoch {
		return errors.New("binding generation/epoch differs from profile")
	}
	if !candidate.CompatibleWith(generation, epoch, now) {
		return errors.New("binding is stale or expired")
	}
	if len(candidate.Fallbacks) != len(profile.Fallbacks) {
		return errors.New("binding fallback count differs from profile")
	}
	for i := range profile.Fallbacks {
		if candidate.Fallbacks[i].Hash() != profile.Fallbacks[i].Hash() {
			return fmt.Errorf("binding fallback %d differs from profile", i)
		}
	}
	return nil
}

func validateRuntimeProviderReadiness(m *Manager, candidate *DNSPathBinding) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	selected := make([]DNSPathID, 0, 1+len(candidate.Fallbacks))
	selected = append(selected, candidate.Primary)
	selected = append(selected, candidate.Fallbacks...)
	for _, path := range selected {
		h := path.Hash()
		if _, ok := m.providers[h]; !ok {
			return fmt.Errorf("provider %s is not registered", path.Family)
		}
		prepared, ok := m.prepared[h]
		if !ok || prepared.Generation != candidate.ConfigGeneration {
			return fmt.Errorf("provider %s is not prepared for generation %d", path.Family, candidate.ConfigGeneration)
		}
	}
	// Promotion requires the primary to be actually usable now. Fallbacks are
	// prepared and evidence-validated above, but may be temporarily degraded;
	// Resolve already skips fallback paths that are not READY/AVAILABLE.
	primaryHealth, ok := m.health[candidate.Primary.Hash()]
	if !ok || primaryHealth == nil || (primaryHealth.State != CapReady && primaryHealth.State != CapAvailable) {
		return fmt.Errorf("primary provider %s is not ready", candidate.Primary.Family)
	}
	return nil
}

func (t *Transaction) abort(reason string) {
	t.Phase = PhaseAborted
	t.Reason = reason
	t.EndedAt = time.Now()
}

func (t *Transaction) rollback(m *Manager, reason string) {
	t.Phase = PhaseRollback
	t.Reason = reason
	if t.LastGood != nil {
		m.restoreLastGood(t.LastGood)
	}
	t.EndedAt = time.Now()
}
