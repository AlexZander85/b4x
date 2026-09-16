package discovery

import (
	"sort"
	"strconv"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/validation"
)

type HintAction string

const (
	HintBoost   HintAction = "boost"
	HintPenalty HintAction = "penalty"
	HintDefer   HintAction = "defer"
)

type SearchHint struct {
	Candidate  string
	Action     HintAction
	Weight     int
	Provenance string
	Threshold  uint64
}
type GuidedSearchPlan struct {
	Baseline              []string
	Ordered               []string
	Hints                 []SearchHint
	SynthesizedCandidates []string
	ExhaustiveFallback    bool
	Explanation           string
}

func CompileHintPlan(prior detector.DiscoverySearchPrior, current []string, hints []SearchHint) GuidedSearchPlan {
	p := GuidedSearchPlan{Baseline: append([]string(nil), current...), ExhaustiveFallback: true, Explanation: "hints reorder bounded search; baseline and exhaustive fallback retained"}
	seen := map[string]bool{}
	for _, x := range current {
		seen[x] = true
		p.Ordered = append(p.Ordered, x)
	}
	valid := hints[:0]
	for _, h := range hints {
		if h.Candidate == "" || h.Provenance == "" {
			continue
		}
		valid = append(valid, h)
		if !seen[h.Candidate] {
			p.Ordered = append(p.Ordered, h.Candidate)
			seen[h.Candidate] = true
		}
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].Action != valid[j].Action {
			return valid[i].Action == HintBoost
		}
		return valid[i].Weight > valid[j].Weight
	})
	p.Hints = append([]SearchHint(nil), valid...)
	if prior.Valid() {
		ordered, preferred, deferred := applyPriorOrder(p.Ordered, len(current), prior)
		p.Ordered = ordered
		p.Explanation += "; detector prior ranked " + strconv.Itoa(preferred) + " preferred, deferred " + strconv.Itoa(deferred) + " (excluded targets stay visible)"
	}
	return p
}

// CompileHintPlanWithSynthesized preserves the existing planner and appends
// immutable synthesized candidate references to the same Ordered pipeline.
// Baselines remain the untouched prefix and exhaustive fallback remains on.
func CompileHintPlanWithSynthesized(prior detector.DiscoverySearchPrior, current []string, hints []SearchHint, synthesized []string) GuidedSearchPlan {
	p := CompileHintPlan(prior, current, hints)
	return MergeSynthesizedCandidates(p, synthesized)
}

func MergeSynthesizedCandidates(plan GuidedSearchPlan, synthesized []string) GuidedSearchPlan {
	seen := make(map[string]struct{}, len(plan.Ordered)+len(synthesized))
	for _, id := range plan.Ordered { if id != "" { seen[id] = struct{}{} } }
	for _, id := range synthesized {
		if id == "" { continue }
		if _, exists := seen[id]; exists { continue }
		seen[id] = struct{}{}
		plan.SynthesizedCandidates = append(plan.SynthesizedCandidates, id)
		plan.Ordered = append(plan.Ordered, id)
	}
	if len(plan.SynthesizedCandidates) > 0 {
		plan.Explanation += "; synthesized candidates share the existing Discovery evaluation/scoring pipeline"
	}
	return plan
}

func applyPriorOrder(ordered []string, baselineLen int, prior detector.DiscoverySearchPrior) ([]string, int, int) {
	preferred, deferred := 0, 0
	if baselineLen >= len(ordered) {
		return ordered, preferred, deferred
	}
	ext := ordered[baselineLen:]
	excluded := make(map[string]bool, len(prior.ExcludedTargets))
	for _, e := range prior.ExcludedTargets {
		excluded[e] = true
	}
	picked := make(map[string]bool, len(prior.TargetOrder))
	head := make([]string, 0, len(prior.TargetOrder))
	for _, t := range prior.TargetOrder {
		if !picked[t] && containsCandidate(ext, t) {
			head = append(head, t)
			picked[t] = true
			preferred++
		}
	}
	middle := make([]string, 0, len(ext))
	tail := make([]string, 0, len(prior.ExcludedTargets))
	for _, c := range ext {
		switch {
		case picked[c]:
		case excluded[c]:
			tail = append(tail, c)
			deferred++
		default:
			middle = append(middle, c)
		}
	}
	out := append([]string(nil), ordered[:baselineLen]...)
	out = append(out, head...)
	out = append(out, middle...)
	out = append(out, tail...)
	return out, preferred, deferred
}
func (p GuidedSearchPlan) Valid() bool {
	return len(p.Baseline) > 0 && len(p.Ordered) >= len(p.Baseline) && p.ExhaustiveFallback
}

func CausalEligibleCandidates(family, authority string, candidates []string) (eligible, forbidden []string) {
	entry, ok := validation.CausalEligibilityByFamily(family)
	if !ok {
		return nil, append([]string(nil), candidates...)
	}
	eligible = make([]string, 0, len(candidates))
	for _, c := range candidates {
		if causalCandidateAllowed(entry, authority, c) {
			eligible = append(eligible, c)
		} else {
			forbidden = append(forbidden, c)
		}
	}
	for _, m := range entry.MandatoryNarrowerFamilies {
		if !containsCandidate(eligible, m) {
			eligible = append(eligible, m)
		}
	}
	return eligible, forbidden
}

func causalCandidateAllowed(entry validation.CausalEligibility, authority, candidate string) bool {
	if containsCandidate(entry.ForbiddenCandidateFamilies, candidate) {
		return false
	}
	if candidate == "scoped_transport" && !validation.TransportAuthorized(entry.Family, authority) {
		return false
	}
	return true
}

func CompileEligiblePlan(family, authority string, prior detector.DiscoverySearchPrior, current []string, hints []SearchHint) GuidedSearchPlan {
	eligible, forbidden := CausalEligibleCandidates(family, authority, current)
	if len(eligible) == 0 {
		return GuidedSearchPlan{
			ExhaustiveFallback: true,
			Explanation:        "causal eligibility matrix denies every candidate for failure family " + family + " (authority " + authority + ")",
		}
	}
	entry, ok := validation.CausalEligibilityByFamily(family)
	if !ok {
		return GuidedSearchPlan{ExhaustiveFallback: true, Explanation: "unknown failure family " + family}
	}
	filtered := hints[:0]
	for _, h := range hints {
		if !causalCandidateAllowed(entry, authority, h.Candidate) {
			continue
		}
		filtered = append(filtered, h)
	}
	p := CompileHintPlan(prior, eligible, filtered)
	if len(forbidden) > 0 {
		p.Explanation = "FB-31 eligibility dropped " + strconv.Itoa(len(forbidden)) + " candidate(s) for " + family + "; " + p.Explanation
	}
	return p
}

func CompileEligiblePlanWithSynthesized(family, authority string, prior detector.DiscoverySearchPrior, current []string, hints []SearchHint, synthesized []string) GuidedSearchPlan {
	return MergeSynthesizedCandidates(CompileEligiblePlan(family, authority, prior, current, hints), synthesized)
}

func containsCandidate(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
