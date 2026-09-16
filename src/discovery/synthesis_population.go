package discovery

import (
	"errors"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
)

const maxSynthesisParents = 6

// SynthesisPopulationState is run-local bookkeeping only. It prevents
// canonical duplicates and failed-candidate replay across measured
// generations; it is never persisted as a second optimizer store.
type SynthesisPopulationState struct {
	SeenCanonical map[string]struct{}
	FailedIDs     map[string]struct{}
	Rejected      map[string]string
	Generated     int
}

func NewSynthesisPopulationState(req SynthesisRequest, existingCanonicalHashes map[string]struct{}) *SynthesisPopulationState {
	state := &SynthesisPopulationState{
		SeenCanonical: make(map[string]struct{}, len(existingCanonicalHashes)+int(req.Limits.normalized().MaxCandidates)),
		FailedIDs:     make(map[string]struct{}, len(req.FailedCandidateIDs)),
		Rejected:      map[string]string{},
	}
	for hash := range existingCanonicalHashes {
		state.SeenCanonical[hash] = struct{}{}
	}
	for _, id := range req.FailedCandidateIDs {
		if id != "" {
			state.FailedIDs[id] = struct{}{}
		}
	}
	return state
}

// SeedPopulation creates only generation zero. Later generations must be
// requested after network outcomes have selected measured parents.
func (p SynthesisPlanner) SeedPopulation(req SynthesisRequest, prior detector.DiscoverySearchPrior, state *SynthesisPopulationState) ([]SynthesizedCandidatePlan, error) {
	if state == nil {
		return nil, errors.New("synthesis population state required")
	}
	if err := p.Grammar.Validate(); err != nil {
		return nil, err
	}
	if !req.Valid(req.RequestedAt) || !prior.Valid() || prior.Scope != req.Scope || prior.ProfileID != req.BlockingProfileID || prior.BehavioralEvidenceID != req.BehavioralEvidenceID {
		return nil, errors.New("exact-scope synthesis request and behavioral prior required")
	}
	limits := req.Limits.normalized()
	seedOps := p.seedOperations(prior, limits, req.SafeFakeProfileIDs)
	trigger := CandidateTrigger{Phase: "complete-reassembled-clienthello", Marker: "host-start"}
	population := make([]SynthesizedCandidatePlan, 0, minInt(len(seedOps), maxSynthesisParents))
	for _, operation := range seedOps {
		if state.Generated >= int(limits.MaxCandidates) || len(population) >= maxSynthesisParents {
			break
		}
		candidate, err := newSynthesizedCandidate(
			req,
			0,
			nil,
			trigger,
			[]CandidateOperation{operation},
			action.RepresentationNormalTCP,
			[]string{"current-action-authorization", "complete-clienthello"},
			CandidateCost{},
			CandidateRisk{},
			[]string{"behavioral-seed"},
			req.RequestedAt,
		)
		if err != nil {
			return nil, err
		}
		validation := p.ValidateCandidate(req, prior, candidate)
		if !validation.Valid {
			state.Rejected[candidate.CandidateID] = validation.Reason
			continue
		}
		candidate.StaticCost, candidate.Risk = validation.Cost, validation.Risk
		if _, duplicate := state.SeenCanonical[candidate.CanonicalHash]; duplicate {
			state.Rejected[candidate.CandidateID] = "canonical duplicate"
			continue
		}
		if _, failed := state.FailedIDs[candidate.CandidateID]; failed {
			state.Rejected[candidate.CandidateID] = "candidate already failed in current context"
			continue
		}
		state.SeenCanonical[candidate.CanonicalHash] = struct{}{}
		state.Generated++
		population = append(population, candidate)
	}
	orderCandidates(population, prior, req.DeterministicSeed)
	return population, nil
}

// NextPopulation mutates/crosses only parents selected after measured network
// fitness. Parent order is therefore meaningful: evolveGeneration spends its
// bounded quota on better measured parents first.
func (p SynthesisPlanner) NextPopulation(req SynthesisRequest, prior detector.DiscoverySearchPrior, parents []SynthesizedCandidatePlan, generation uint8, state *SynthesisPopulationState) ([]SynthesizedCandidatePlan, error) {
	if state == nil {
		return nil, errors.New("synthesis population state required")
	}
	limits := req.Limits.normalized()
	if generation == 0 || generation >= limits.MaxGenerations || len(parents) == 0 || state.Generated >= int(limits.MaxCandidates) {
		return nil, nil
	}
	remaining := int(limits.MaxCandidates) - state.Generated
	generationLimits := limits
	if remaining < int(generationLimits.MaxCandidates) {
		generationLimits.MaxCandidates = uint16(remaining)
	}
	next, err := p.evolveGeneration(req, prior, parents, p.seedOperations(prior, limits, req.SafeFakeProfileIDs), generation, state.SeenCanonical, state.FailedIDs, state.Rejected, generationLimits)
	if err != nil {
		return nil, err
	}
	if len(next) > remaining {
		next = next[:remaining]
	}
	state.Generated += len(next)
	orderCandidates(next, prior, req.DeterministicSeed+int64(generation))
	return next, nil
}
