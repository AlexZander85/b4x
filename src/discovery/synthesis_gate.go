package discovery

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
)

type SynthesisGateInput struct {
	UserOptIn                    bool
	PersistentRegressionQualified bool
	Assessment                   monitor.MonitorAssessment
	Profile                      NetworkDiagnosticProfile
	Prior                        detector.DiscoverySearchPrior
	CurrentConfigGeneration      uint64
	RolloutIdle                  bool
	VisibilityReady              bool
	MandatoryControlsReady       bool
	Now                          time.Time
}

func CheckAutomaticSynthesisGate(in SynthesisGateInput) error {
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
	if in.CurrentConfigGeneration == 0 || in.Profile.Scope.ConfigGeneration != in.CurrentConfigGeneration || in.Prior.Scope.ConfigGeneration != in.CurrentConfigGeneration {
		observability.RecordSynthesisViolation(observability.MetricSynthesisStaleGenerationUsed)
		return errors.New("stale synthesis generation")
	}
	if !in.RolloutIdle { return errors.New("active rollout suppresses synthesis") }
	if !in.VisibilityReady { return errors.New("visibility/readiness gate suppresses synthesis") }
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
