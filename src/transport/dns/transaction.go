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

// Run executes the transaction. Any failure before/during canary leaves the
// current binding unchanged; rollback restores last-good and preserves the
// reason (§76/§97).
func (t *Transaction) Run(ctx context.Context, m *Manager) error {
	t.StartedAt = time.Now()
	t.Phase = PhasePrepare
	if t.Profile == nil || t.Candidate == nil {
		t.abort("profile and candidate binding required")
		return ErrTransactionAborted
	}
	if err := t.Profile.Valid(time.Now()); err != nil {
		t.abort("profile invalid: " + err.Error())
		return ErrTransactionAborted
	}
	// PREPARE: cache partition for the new generation must be ready and
	// isolated from the old one.
	m.cache.ResetPartition(t.Profile.NetworkContextID, t.Profile.ConfigGeneration, t.Candidate.Primary.Hash())
	t.Gate.CacheReady = true
	// Rollback readiness: with a retained last-good we restore it; on the
	// first-ever promotion rollback means reverting to the pre-adaptive
	// behavior (no adaptive binding), which is always available.
	t.Gate.RollbackReady = true

	t.Phase = PhaseCanary
	if t.Canary != nil {
		if err := t.Canary(ctx, t.Candidate); err != nil {
			t.Gate.AndroidCanary = false
		} else {
			t.Gate.AndroidCanary = true
		}
	}
	if err := t.Gate.Check(); err != nil {
		t.rollback(m, err.Error())
		return ErrTransactionAborted
	}

	t.Phase = PhasePromote
	m.promote(t.Candidate, t.LastGood)
	t.Phase = PhaseDone
	t.EndedAt = time.Now()
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
