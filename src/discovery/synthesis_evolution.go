package discovery

import (
	"fmt"
	"sort"

	"github.com/daniellavrushin/b4/detector"
)

const maxSynthesisCandidatesPerGeneration = 8

// evolveGeneration implements the bounded Geneva-inspired step without a
// second optimizer/runtime. Every offspring is canonicalized by
// newSynthesizedCandidate and admitted only through ValidateCandidate.
func (p SynthesisPlanner) evolveGeneration(
	req SynthesisRequest,
	prior detector.DiscoverySearchPrior,
	parents []SynthesizedCandidatePlan,
	seedOps []CandidateOperation,
	generation uint8,
	seen map[string]struct{},
	failed map[string]struct{},
	rejected map[string]string,
	limits SynthesisLimits,
) ([]SynthesizedCandidatePlan, error) {
	maxGeneration := maxSynthesisCandidatesPerGeneration
	if remaining := int(limits.MaxCandidates); remaining < maxGeneration {
		maxGeneration = remaining
	}
	next := make([]SynthesizedCandidatePlan, 0, maxGeneration)

	try := func(parentIDs []string, trigger CandidateTrigger, ops []CandidateOperation, representationCandidate SynthesizedCandidatePlan, trace string) (bool, error) {
		if len(next) >= maxGeneration || len(ops) == 0 || len(ops) > int(limits.MaxActions) {
			return false, nil
		}
		candidate, err := newSynthesizedCandidate(
			req,
			generation,
			parentIDs,
			trigger,
			ops,
			representationCandidate.Representation,
			representationCandidate.Preconditions,
			CandidateCost{},
			CandidateRisk{},
			[]string{trace},
			req.RequestedAt,
		)
		if err != nil {
			return false, err
		}
		validation := p.ValidateCandidate(req, prior, candidate)
		if !validation.Valid {
			rejected[candidate.CandidateID] = validation.Reason
			return false, nil
		}
		candidate.StaticCost, candidate.Risk = validation.Cost, validation.Risk
		if _, duplicate := seen[candidate.CanonicalHash]; duplicate {
			return false, nil
		}
		if _, wasFailed := failed[candidate.CandidateID]; wasFailed {
			rejected[candidate.CandidateID] = "candidate already failed in current context"
			return false, nil
		}
		seen[candidate.CanonicalHash] = struct{}{}
		next = append(next, candidate)
		return true, nil
	}

	// Keep the population diverse under the hard eight-candidate generation
	// cap: at most three add mutations, two parameter/marker mutations, and one
	// each trigger, replace and crossover before fallback mutations fill holes.
	if err := p.evolveAdds(parents, seedOps, generation, 3, try); err != nil {
		return nil, err
	}
	if err := p.evolveParameters(parents, generation, 2, try); err != nil {
		return nil, err
	}
	if err := p.evolveTriggers(parents, generation, 1, try); err != nil {
		return nil, err
	}
	if err := p.evolveReplacements(parents, seedOps, generation, 1, try); err != nil {
		return nil, err
	}
	if err := p.evolveCrossovers(parents, generation, 1, try); err != nil {
		return nil, err
	}
	if len(next) < maxGeneration {
		if err := p.evolveRemovalsAndSwaps(parents, generation, maxGeneration-len(next), try); err != nil {
			return nil, err
		}
	}
	return next, nil
}

type evolutionTry func([]string, CandidateTrigger, []CandidateOperation, SynthesizedCandidatePlan, string) (bool, error)

func (p SynthesisPlanner) evolveAdds(parents []SynthesizedCandidatePlan, seeds []CandidateOperation, generation uint8, quota int, try evolutionTry) error {
	accepted := 0
	for _, parent := range parents {
		for _, seed := range seeds {
			ops := append(cloneCandidateOperations(parent.Operations), cloneCandidateOperation(seed))
			ok, err := try([]string{parent.CandidateID}, parent.Trigger, ops, parent, fmt.Sprintf("g%d:add:%s", generation, seed.Family))
			if err != nil {
				return err
			}
			if ok {
				accepted++
				break
			}
		}
		if accepted >= quota {
			break
		}
	}
	return nil
}

func (p SynthesisPlanner) evolveParameters(parents []SynthesizedCandidatePlan, generation uint8, quota int, try evolutionTry) error {
	accepted := 0
	for _, parent := range parents {
		for opIndex, operation := range parent.Operations {
			definition, ok := p.Grammar.Operator(operation.Family)
			if !ok {
				continue
			}
			keys := make([]string, 0, len(definition.ParameterDomain))
			for key := range definition.ParameterDomain {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				value, ok := neighboringDomainValue(operation.Params[key], definition.ParameterDomain[key])
				if !ok {
					continue
				}
				ops := cloneCandidateOperations(parent.Operations)
				if ops[opIndex].Params == nil {
					ops[opIndex].Params = map[string]string{}
				}
				ops[opIndex].Params[key] = value
				acceptedMutation, err := try([]string{parent.CandidateID}, parent.Trigger, ops, parent, fmt.Sprintf("g%d:param:%s:%s=%s", generation, operation.Family, key, value))
				if err != nil {
					return err
				}
				if acceptedMutation {
					accepted++
					break
				}
			}
			if accepted >= quota {
				break
			}
		}
		if accepted >= quota {
			break
		}
	}
	return nil
}

func (p SynthesisPlanner) evolveTriggers(parents []SynthesizedCandidatePlan, generation uint8, quota int, try evolutionTry) error {
	accepted := 0
	for _, parent := range parents {
		for _, domain := range p.Grammar.TriggerDomains {
			if domain.Phase == parent.Trigger.Phase || !triggerMarkerAllowed(parent.Trigger.Marker, domain.Markers) {
				continue
			}
			trigger := CandidateTrigger{Phase: domain.Phase, Marker: parent.Trigger.Marker}
			ok, err := try([]string{parent.CandidateID}, trigger, cloneCandidateOperations(parent.Operations), parent, fmt.Sprintf("g%d:trigger:%s", generation, domain.Phase))
			if err != nil {
				return err
			}
			if ok {
				accepted++
				break
			}
		}
		if accepted >= quota {
			break
		}
	}
	return nil
}

func (p SynthesisPlanner) evolveReplacements(parents []SynthesizedCandidatePlan, seeds []CandidateOperation, generation uint8, quota int, try evolutionTry) error {
	accepted := 0
	for _, parent := range parents {
		for opIndex, operation := range parent.Operations {
			current, ok := p.Grammar.Operator(operation.Family)
			if !ok {
				continue
			}
			for _, seed := range seeds {
				replacement, ok := p.Grammar.Operator(seed.Family)
				if !ok || seed.Family == operation.Family || replacement.RiskTier != current.RiskTier {
					continue
				}
				ops := cloneCandidateOperations(parent.Operations)
				ops[opIndex] = cloneCandidateOperation(seed)
				replaced, err := try([]string{parent.CandidateID}, parent.Trigger, ops, parent, fmt.Sprintf("g%d:replace:%s>%s", generation, operation.Family, seed.Family))
				if err != nil {
					return err
				}
				if replaced {
					accepted++
					break
				}
			}
			if accepted >= quota {
				break
			}
		}
		if accepted >= quota {
			break
		}
	}
	return nil
}

func (p SynthesisPlanner) evolveCrossovers(parents []SynthesizedCandidatePlan, generation uint8, quota int, try evolutionTry) error {
	accepted := 0
	for i := 0; i < len(parents); i++ {
		for j := i + 1; j < len(parents); j++ {
			a, b := parents[i], parents[j]
			if a.Scope != b.Scope || a.ConfigGeneration != b.ConfigGeneration || a.Representation != b.Representation || a.Trigger.Phase != b.Trigger.Phase || a.Trigger.Marker != b.Trigger.Marker {
				continue
			}
			left := (len(a.Operations) + 1) / 2
			right := len(b.Operations) / 2
			ops := append(cloneCandidateOperations(a.Operations[:left]), cloneCandidateOperations(b.Operations[right:])...)
			crossed, err := try([]string{a.CandidateID, b.CandidateID}, a.Trigger, ops, a, fmt.Sprintf("g%d:crossover", generation))
			if err != nil {
				return err
			}
			if crossed {
				accepted++
			}
			if accepted >= quota {
				return nil
			}
		}
	}
	return nil
}

func (p SynthesisPlanner) evolveRemovalsAndSwaps(parents []SynthesizedCandidatePlan, generation uint8, quota int, try evolutionTry) error {
	accepted := 0
	for _, parent := range parents {
		if len(parent.Operations) > 1 {
			for index := range parent.Operations {
				ops := append(cloneCandidateOperations(parent.Operations[:index]), cloneCandidateOperations(parent.Operations[index+1:])...)
				removed, err := try([]string{parent.CandidateID}, parent.Trigger, ops, parent, fmt.Sprintf("g%d:remove:%d", generation, index))
				if err != nil {
					return err
				}
				if removed {
					accepted++
				}
				if accepted >= quota {
					return nil
				}
			}
			for index := 0; index+1 < len(parent.Operations); index++ {
				ops := cloneCandidateOperations(parent.Operations)
				ops[index], ops[index+1] = ops[index+1], ops[index]
				swapped, err := try([]string{parent.CandidateID}, parent.Trigger, ops, parent, fmt.Sprintf("g%d:swap:%d", generation, index))
				if err != nil {
					return err
				}
				if swapped {
					accepted++
				}
				if accepted >= quota {
					return nil
				}
			}
		}
	}
	return nil
}

func neighboringDomainValue(current string, domain []string) (string, bool) {
	if len(domain) < 2 {
		return "", false
	}
	for i, value := range domain {
		if value != current {
			continue
		}
		if i+1 < len(domain) {
			return domain[i+1], true
		}
		return domain[i-1], true
	}
	return domain[0], true
}

func triggerMarkerAllowed(marker string, markers []string) bool {
	if marker == "" {
		return true
	}
	for _, candidate := range markers {
		if candidate == marker {
			return true
		}
	}
	return false
}

func cloneCandidateOperation(operation CandidateOperation) CandidateOperation {
	out := CandidateOperation{Family: operation.Family}
	if operation.Params != nil {
		out.Params = make(map[string]string, len(operation.Params))
		for key, value := range operation.Params {
			out.Params[key] = value
		}
	}
	return out
}
