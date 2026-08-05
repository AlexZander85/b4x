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
	Baseline           []string
	Ordered            []string
	Hints              []SearchHint
	ExhaustiveFallback bool
	Explanation        string
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
	_ = prior
	return p
}
func (p GuidedSearchPlan) Valid() bool {
	return len(p.Baseline) > 0 && len(p.Ordered) >= len(p.Baseline) && p.ExhaustiveFallback
}

// CausalEligibleCandidates applies the FB-31 causal eligibility matrix to a
// candidate family list for a failure family (FB-31, b4x-cka):
//
//   - forbidden candidate families are dropped and reported;
//   - mandatory narrower families are retained unconditionally (a hint or
//     prior may reorder, never remove them — v1.2 §20.2);
//   - scoped transport (WARP/SOCKS/TUN) survives only when the evidence
//     authority authorizes it (authoritative-abd or above, FB-30);
//   - an unknown failure family fails closed: nothing is eligible.
//
// This is the single eligibility gate guided search and transport fallback
// planners call before composing candidate sets (v1.2 §21 mapping).
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
	// Mandatory narrower families are never dropped by eligibility filtering.
	for _, m := range entry.MandatoryNarrowerFamilies {
		if !containsCandidate(eligible, m) {
			eligible = append(eligible, m)
		}
	}
	return eligible, forbidden
}

// causalCandidateAllowed is the single FB-31 eligibility predicate for one
// candidate family under an evidence authority. It is shared by candidate
// filtering and hint filtering so both paths see the full matrix forbidden
// set (a hint on a matrix-forbidden family is dropped even when that family
// is not part of the current candidate set).
func causalCandidateAllowed(entry validation.CausalEligibility, authority, candidate string) bool {
	if containsCandidate(entry.ForbiddenCandidateFamilies, candidate) {
		return false
	}
	if candidate == "scoped_transport" && !validation.TransportAuthorized(entry.Family, authority) {
		return false
	}
	return true
}

// CompileEligiblePlan is the FB-31 guided-search planner entry point: it
// applies the causal eligibility matrix to the current candidate set, drops
// hints targeting forbidden families, retains mandatory narrower families
// unconditionally, and only then delegates to CompileHintPlan. Unknown
// failure family fails closed: nothing is eligible, the plan is invalid
// (empty Baseline) and the explanation records the denial.
func CompileEligiblePlan(family, authority string, prior detector.DiscoverySearchPrior, current []string, hints []SearchHint) GuidedSearchPlan {
	eligible, forbidden := CausalEligibleCandidates(family, authority, current)
	if len(eligible) == 0 {
		return GuidedSearchPlan{
			ExhaustiveFallback: true,
			Explanation:        "causal eligibility matrix denies every candidate for failure family " + family + " (authority " + authority + ")",
		}
	}
	entry, ok := validation.CausalEligibilityByFamily(family)
	if !ok { // unreachable: len(eligible)>0 implies a known family; keep fail-closed
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

func containsCandidate(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
