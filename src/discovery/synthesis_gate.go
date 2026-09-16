package discovery

import (
	"errors"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
)

type SynthesisGateInput struct {
	UserOptIn                     bool
	PersistentRegressionQualified bool
	Assessment                    monitor.MonitorAssessment
	Profile                       NetworkDiagnosticProfile
	Prior                         detector.DiscoverySearchPrior
	CurrentConfigGeneration       uint64

	// Existing subsystem state only. AFS does not own a second resource,
	// cleanup, cooldown or authorization subsystem; callers project those
	// owners into this preflight envelope.
	RolloutIdle                bool
	NoConflictingRun           bool
	VisibilityReady            bool
	MandatoryControlsReady     bool
	TargetPlanComplete         bool
	ActiveTestAuthorized       bool
	ResourceBudgetAvailable    bool
	CleanupComplete            bool
	CatalogEscalationSatisfied bool
	NextEligibleAt             time.Time
	Now                        time.Time
}

func CheckAutomaticSynthesisGate(in SynthesisGateInput) error {
	if in.Now.IsZero() {
		return errors.New("synthesis gate requires current time")
	}
	if !in.UserOptIn {
		observability.RecordSynthesisViolation(observability.MetricSynthesisWithoutUserOptIn)
		return errors.New("adaptive strategy synthesis is not user-enabled")
	}
	if !in.PersistentRegressionQualified {
		observability.RecordSynthesisViolation(observability.MetricSynthesisWithoutPersistentRegression)
		return errors.New("persistent monitoring regression is not qualified")
	}
	if !in.Assessment.Valid(in.Now) || !in.Profile.Valid(in.Now) || !in.Prior.Valid() {
		observability.RecordSynthesisViolation(observability.MetricSynthesisWithoutFreshProfile)
		return errors.New("fresh monitoring assessment, diagnostic profile and DDI prior are required")
	}
	if in.Assessment.Scope != in.Profile.Scope || in.Prior.Scope != in.Profile.Scope {
		observability.RecordSynthesisViolation(observability.MetricSynthesisScopeEscape)
		return errors.New("monitor/profile/prior scope mismatch")
	}
	if strings.TrimSpace(in.Profile.Scope.ServiceProfileID) == "" || strings.TrimSpace(in.Profile.Scope.ComponentID) == "" {
		observability.RecordSynthesisViolation(observability.MetricSynthesisScopeEscape)
		return errors.New("exact service profile and component scope are required")
	}
	if in.CurrentConfigGeneration == 0 || in.Profile.Scope.ConfigGeneration != in.CurrentConfigGeneration || in.Prior.Scope.ConfigGeneration != in.CurrentConfigGeneration {
		observability.RecordSynthesisViolation(observability.MetricSynthesisStaleGenerationUsed)
		return errors.New("stale synthesis generation")
	}
	if !in.RolloutIdle {
		return errors.New("active rollout suppresses synthesis")
	}
	if !in.NoConflictingRun {
		return errors.New("active Discovery or synthesis run suppresses synthesis")
	}
	if !in.NextEligibleAt.IsZero() && in.Now.Before(in.NextEligibleAt) {
		return errors.New("synthesis cooldown has not expired")
	}
	if !in.CleanupComplete {
		observability.RecordSynthesisViolation(observability.MetricSynthesisCleanupIncomplete)
		return errors.New("previous synthesis cleanup is incomplete")
	}
	if !in.ResourceBudgetAvailable {
		return errors.New("synthesis resource budget is unavailable")
	}
	if !in.CatalogEscalationSatisfied {
		return errors.New("catalog strategy escalation has not been exhausted")
	}
	if !in.TargetPlanComplete {
		return errors.New("complete target plan is required")
	}
	if !in.ActiveTestAuthorized {
		return errors.New("target is not authorized for bounded active testing")
	}
	if !in.VisibilityReady {
		return errors.New("visibility/readiness gate suppresses synthesis")
	}
	if !in.MandatoryControlsReady {
		observability.RecordSynthesisViolation(observability.MetricSynthesisMissingMandatoryControl)
		return errors.New("mandatory target/control matrix is unavailable")
	}
	if in.Profile.Blocking.Behavioral == nil || in.Prior.BehavioralEvidenceID == "" || in.Prior.BehavioralEvidenceID != in.Profile.Blocking.Behavioral.EvidenceID {
		observability.RecordSynthesisViolation(observability.MetricSynthesisWithoutFreshProfile)
		return errors.New("fresh behavioral evidence is required for automatic synthesis")
	}
	return nil
}
