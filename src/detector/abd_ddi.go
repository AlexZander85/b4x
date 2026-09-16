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
	return e.EnvelopeID != "" && e.Profile.Fresh(now) && e.Profile.Scope == e.Scope && e.Scope.Valid() && (e.ExpiresAt.IsZero() || now.Before(e.ExpiresAt))
}

type DiscoverySearchPrior struct {
	Scope                monitor.MonitorScopeKey
	ProfileID            string
	BehavioralEvidenceID string
	Hypotheses           []string
	TargetOrder          []string
	ExcludedTargets      []string
	SupportedOperators   []StrategyOperatorFamily
	PenalizedOperators   []StrategyOperatorFamily
	ExcludedOperators    []StrategyOperatorFamily
	CoverageDenominator  int
	MandatoryBaselines   []string
	Applied              bool
	Explanation          string
}

func (p DiscoverySearchPrior) Valid() bool {
	if p.ProfileID == "" || !p.Scope.Valid() || p.CoverageDenominator <= 0 || len(p.MandatoryBaselines) == 0 {
		return false
	}
	return !operatorListsOverlap(p.SupportedOperators, p.ExcludedOperators) && !operatorListsOverlap(p.PenalizedOperators, p.ExcludedOperators)
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
	if b := in.Envelope.Profile.Behavioral; b != nil {
		p.BehavioralEvidenceID = b.EvidenceID
		p.SupportedOperators, p.PenalizedOperators, p.ExcludedOperators = compileOperatorConstraints(b.Features)
		p.Explanation = "ABD behavioral evidence constrains synthesis and orders bounded search; current baseline and exhaustive fallback remain mandatory"
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

func compileOperatorConstraints(features []BehaviorFeature) (supported, penalized, excluded []StrategyOperatorFamily) {
	for _, f := range features {
		if f.Confidence <= 0 {
			continue
		}
		supported = append(supported, f.Supports...)
		penalized = append(penalized, f.Penalizes...)
		excluded = append(excluded, f.Excludes...)
	}
	excluded = uniqueOperatorFamilies(excluded)
	excludedSet := make(map[StrategyOperatorFamily]struct{}, len(excluded))
	for _, op := range excluded {
		excludedSet[op] = struct{}{}
	}
	filter := func(in []StrategyOperatorFamily) []StrategyOperatorFamily {
		out := make([]StrategyOperatorFamily, 0, len(in))
		for _, op := range uniqueOperatorFamilies(in) {
			if _, blocked := excludedSet[op]; !blocked {
				out = append(out, op)
			}
		}
		return out
	}
	return filter(supported), filter(penalized), excluded
}

func operatorListsOverlap(a, b []StrategyOperatorFamily) bool {
	seen := make(map[StrategyOperatorFamily]struct{}, len(a))
	for _, op := range a {
		seen[op] = struct{}{}
	}
	for _, op := range b {
		if _, ok := seen[op]; ok {
			return true
		}
	}
	return false
}
