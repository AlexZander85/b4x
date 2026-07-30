package detector

import (
	"errors"
	"sort"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type NetworkDiagnosticProfileEnvelope struct {
	EnvelopeID           string
	Scope                monitor.MonitorScopeKey
	Profile              BlockingProfile
	CreatedAt, ExpiresAt time.Time
	CompatibilityHash    string
}

func (e NetworkDiagnosticProfileEnvelope) Fresh(now time.Time) bool {
	return e.EnvelopeID != "" && e.Profile.Valid() && e.Profile.Scope == e.Scope && e.Scope.Valid() && (e.ExpiresAt.IsZero() || now.Before(e.ExpiresAt))
}

type DiscoverySearchPrior struct {
	Scope               monitor.MonitorScopeKey
	ProfileID           string
	Hypotheses          []string
	TargetOrder         []string
	ExcludedTargets     []string
	CoverageDenominator int
	MandatoryBaselines  []string
	Applied             bool
	Explanation         string
}

func (p DiscoverySearchPrior) Valid() bool {
	return p.ProfileID != "" && p.Scope.Valid() && p.CoverageDenominator > 0 && len(p.MandatoryBaselines) > 0
}

type CandidateCoverageVector struct {
	TargetID                   string
	Functional, Stable, Canary bool
	Covered                    bool
	Excluded                   bool
	ExclusionReason            string
}
type GuidedPlannerInput struct {
	Envelope          NetworkDiagnosticProfileEnvelope
	CurrentBaseline   []string
	CandidateCoverage []CandidateCoverageVector
	RequestedAt       time.Time
}

func BuildDiscoverySearchPrior(in GuidedPlannerInput, now time.Time) (DiscoverySearchPrior, error) {
	if !in.Envelope.Fresh(now) || len(in.CurrentBaseline) == 0 {
		return DiscoverySearchPrior{}, errors.New("fresh DDI envelope and current baseline required")
	}
	p := DiscoverySearchPrior{Scope: in.Envelope.Scope, ProfileID: in.Envelope.Profile.ProfileID, CoverageDenominator: len(in.CandidateCoverage), MandatoryBaselines: append([]string(nil), in.CurrentBaseline...), Applied: true, Explanation: "ABD evidence orders bounded search; current baseline and exhaustive fallback remain mandatory"}
	p.Hypotheses = []string{in.Envelope.Profile.Hypothesis}
	for _, c := range in.CandidateCoverage {
		if c.Excluded {
			p.ExcludedTargets = append(p.ExcludedTargets, c.TargetID)
			continue
		}
		if c.Covered {
			p.TargetOrder = append(p.TargetOrder, c.TargetID)
		}
	}
	sort.Strings(p.TargetOrder)
	sort.Strings(p.ExcludedTargets)
	if !p.Valid() {
		return DiscoverySearchPrior{}, errors.New("invalid discovery prior")
	}
	return p, nil
}
func (p DiscoverySearchPrior) MergeBaseline(candidates []string) []string {
	seen := map[string]bool{}
	out := append([]string(nil), p.MandatoryBaselines...)
	for _, x := range out {
		seen[x] = true
	}
	for _, x := range p.TargetOrder {
		if !seen[x] {
			out = append(out, x)
			seen[x] = true
		}
	}
	for _, x := range candidates {
		if !seen[x] {
			out = append(out, x)
			seen[x] = true
		}
	}
	return out
}
