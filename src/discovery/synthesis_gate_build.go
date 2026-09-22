package discovery

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

// SynthesisGateContext carries the already-decided ABD/monitoring inputs plus
// the projected subsystem flags. BuildSynthesisGateInput assembles the
// canonical AFS preflight from exactly these values; it fabricates nothing and
// never owns a second resource/cleanup/authorization subsystem.
type SynthesisGateContext struct {
	Assessment              monitor.MonitorAssessment
	Blocking                detector.BlockingProfile
	CurrentConfigGeneration uint64
	Baseline                []string
	CandidateCoverage       []detector.CandidateCoverageVector

	UserOptIn                     bool
	PersistentRegressionQualified bool
	RolloutIdle                   bool
	NoConflictingRun              bool
	VisibilityReady               bool
	MandatoryControlsReady        bool
	TargetPlanComplete            bool
	ActiveTestAuthorized          bool
	ResourceBudgetAvailable       bool
	ResourceOwnershipReady        bool
	CleanupComplete               bool
	CatalogEscalationSatisfied    bool
	NextEligibleAt                time.Time
	Now                           time.Time
}

// SynthesisProfileTTL bounds the assembled diagnostic profile/prior lifetime.
const SynthesisProfileTTL = 5 * time.Minute

// BuildSynthesisGateInput assembles the AFS preflight envelope from retained
// ABD outputs through the existing detector/discovery constructors. The
// diagnostic profile and DDI prior are built here; the subsystem flags are
// projected by the caller.
func BuildSynthesisGateInput(in SynthesisGateContext) (SynthesisGateInput, error) {
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	blocking := in.Blocking
	if !blocking.Fresh(now) {
		return SynthesisGateInput{}, errors.New("retained blocking profile is not ready or fresh")
	}
	expires := now.Add(SynthesisProfileTTL)
	if !blocking.CompiledAt.IsZero() {
		if compiled := blocking.CompiledAt.Add(SynthesisProfileTTL); compiled.After(now) && compiled.Before(expires) {
			expires = compiled
		}
	}
	profile, err := NewNetworkDiagnosticProfile(blocking, expires, now)
	if err != nil {
		return SynthesisGateInput{}, err
	}
	envelope := detector.NetworkDiagnosticProfileEnvelope{
		EnvelopeID:        "afs/" + blocking.ProfileID,
		Scope:             blocking.Scope,
		Profile:           blocking,
		CreatedAt:         now,
		ExpiresAt:         expires,
		CompatibilityHash: blocking.ContentHash,
	}
	baseline := append([]string(nil), in.Baseline...)
	if len(baseline) == 0 {
		baseline = []string{"baseline-none", "baseline-production"}
	}
	prior, err := detector.BuildDiscoverySearchPrior(detector.GuidedPlannerInput{
		Envelope:          envelope,
		CurrentBaseline:   baseline,
		CandidateCoverage: append([]detector.CandidateCoverageVector(nil), in.CandidateCoverage...),
		RequestedAt:       now,
	}, now)
	if err != nil {
		return SynthesisGateInput{}, err
	}
	return SynthesisGateInput{
		UserOptIn:                     in.UserOptIn,
		PersistentRegressionQualified: in.PersistentRegressionQualified,
		Assessment:                    in.Assessment,
		Profile:                       profile,
		Prior:                         prior,
		CurrentConfigGeneration:       in.CurrentConfigGeneration,
		RolloutIdle:                   in.RolloutIdle,
		NoConflictingRun:              in.NoConflictingRun,
		VisibilityReady:               in.VisibilityReady,
		MandatoryControlsReady:        in.MandatoryControlsReady,
		TargetPlanComplete:            in.TargetPlanComplete,
		ActiveTestAuthorized:          in.ActiveTestAuthorized,
		ResourceBudgetAvailable:       in.ResourceBudgetAvailable,
		ResourceOwnershipReady:        in.ResourceOwnershipReady,
		CleanupComplete:               in.CleanupComplete,
		CatalogEscalationSatisfied:    in.CatalogEscalationSatisfied,
		NextEligibleAt:                in.NextEligibleAt,
		Now:                           now,
	}, nil
}
