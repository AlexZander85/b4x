package discovery

import (
	"github.com/daniellavrushin/b4/detector"
	"sort"
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
