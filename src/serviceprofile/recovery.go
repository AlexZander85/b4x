package serviceprofile

import "errors"

type RecoveryMode string

const (
	RecoveryDisabled   RecoveryMode = "disabled"
	RecoveryObserve    RecoveryMode = "observe"
	RecoveryRecommend  RecoveryMode = "recommend"
	RecoveryAutoCanary RecoveryMode = "auto-canary"
)

type RecoveryBinding struct {
	ID, ComponentID, ClientScope, ConfigGeneration, RollbackTarget string
	Mode                                                           RecoveryMode
	Ordered                                                        []string
	TTLSeconds, MaxAttempts, CooldownSeconds                       int
	StrictNonRU                                                    bool
}

func ValidateRecovery(b RecoveryBinding) error {
	if b.ID == "" || b.ComponentID == "" || b.ClientScope == "" || b.ConfigGeneration == "" {
		return errors.New("recovery binding requires exact scope and generation")
	}
	if b.ClientScope == "destination-global" || b.ClientScope == "recursive" {
		return errors.New("global or recursive recovery forbidden")
	}
	if b.Mode != RecoveryDisabled && b.Mode != RecoveryObserve && b.Mode != RecoveryRecommend && b.Mode != RecoveryAutoCanary {
		return errors.New("invalid recovery mode")
	}
	if b.Mode == RecoveryAutoCanary && (b.RollbackTarget == "" || b.TTLSeconds <= 0 || b.MaxAttempts <= 0) {
		return errors.New("active recovery requires rollback and lease bounds")
	}
	if b.Mode == RecoveryAutoCanary && b.CooldownSeconds <= 0 {
		return errors.New("active recovery requires cooldown window")
	}
	return nil
}

type RecoveryHealth struct {
	ConfiguredMode, EffectiveMode RecoveryMode
	DegradedReason, LastRollback  string
	FalsePositiveBudget           int
}
type RecoveryUX struct {
	Wording           string
	EvidenceRefs      []string
	Suppressors       []string
	LeaseID           string
	RollbackAvailable bool
	EffectiveMode     RecoveryMode
}

func (u RecoveryUX) Truthful() bool {
	return u.Wording != "" && u.EffectiveMode != "" && (!u.RollbackAvailable || u.LeaseID != "")
}

type RecoveryLease struct {
	ID, BindingID, ClientScope, ComponentID  string
	ConfigGeneration                         uint64
	TTLSeconds, MaxAttempts, CooldownSeconds int
	Active, RolledBack                       bool
}
type RecoveryPromotion struct {
	Mode                RecoveryMode
	EvidenceRefs        []string
	FieldTests          []string
	FalsePositiveBudget int
	Validated           bool
	InvalidReason       string
	Invalidated         bool
}

// Invalidate cancels the promotion because of a material profile, capability
// or network change (SP-23): the promotion must not be usable anymore until
// it is rebuilt against the new configuration generation.
func (p *RecoveryPromotion) Invalidate(reason string) {
	if p == nil || reason == "" {
		return
	}
	p.Invalidated = true
	p.InvalidReason = reason
	p.Validated = false
}

func (p RecoveryPromotion) Ready() bool {
	if p.Invalidated {
		return false
	}
	return p.Validated && len(p.EvidenceRefs) >= 2 && len(p.FieldTests) > 0 && p.FalsePositiveBudget > 0
}

func (l RecoveryLease) Valid() bool {
	return l.ID != "" && l.BindingID != "" && l.ClientScope != "" && l.ComponentID != "" && l.ConfigGeneration > 0 && l.TTLSeconds > 0 && l.MaxAttempts > 0 && l.CooldownSeconds > 0
}
