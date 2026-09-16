package discovery

import (
	"errors"
	"fmt"
	"hash/fnv"
	"sort"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
)

type SynthesisValidationResult struct {
	Valid  bool
	Reason string
	Cost   CandidateCost
	Risk   CandidateRisk
}

type SynthesisPlanResult struct {
	RequestID  string
	Candidates []SynthesizedCandidatePlan
	Rejected   map[string]string
	Exhausted  bool
	Reason     string
}

type SynthesisPlanner struct {
	Grammar StrategyGrammar
}

func NewSynthesisPlanner() SynthesisPlanner {
	return SynthesisPlanner{Grammar: AutomaticStrategyGrammarV1()}
}

func (p SynthesisPlanner) ValidateCandidate(req SynthesisRequest, prior detector.DiscoverySearchPrior, candidate SynthesizedCandidatePlan) SynthesisValidationResult {
	result := SynthesisValidationResult{}
	if err := p.Grammar.Validate(); err != nil {
		result.Reason = err.Error()
		return result
	}
	if !req.Valid(req.RequestedAt) {
		result.Reason = "invalid or stale synthesis request"
		return result
	}
	if !prior.Valid() || prior.Scope != req.Scope || prior.ProfileID != req.BlockingProfileID || prior.BehavioralEvidenceID != req.BehavioralEvidenceID {
		result.Reason = "fresh exact-scope behavioral DDI prior required"
		return result
	}
	if candidate.Scope != req.Scope || candidate.ConfigGeneration != req.ConfigGeneration || candidate.GrammarVersion != p.Grammar.Version || !candidate.ValidIdentity() {
		result.Reason = "candidate scope/generation/identity mismatch"
		return result
	}
	if !p.Grammar.TriggerAllowed(candidate.Trigger) {
		result.Reason = "trigger outside finite grammar"
		return result
	}
	limits := req.Limits.normalized()
	maxActions := limits.MaxActions
	if p.Grammar.MaxActions < maxActions {
		maxActions = p.Grammar.MaxActions
	}
	maxBranches := limits.MaxBranches
	if p.Grammar.MaxBranches < maxBranches {
		maxBranches = p.Grammar.MaxBranches
	}
	maxAmplification := limits.MaxAmplification
	if p.Grammar.MaxAmplification < maxAmplification {
		maxAmplification = p.Grammar.MaxAmplification
	}
	if len(candidate.Operations) == 0 || len(candidate.Operations) > int(maxActions) {
		result.Reason = "candidate action count exceeds bound"
		return result
	}
	if reason := candidateActionBridgeShape(candidate.Operations); reason != "" {
		result.Reason = reason
		return result
	}

	excluded := operatorSet(prior.ExcludedOperators)
	cost := CandidateCost{Actions: uint8(len(candidate.Operations)), EstimatedPackets: 1, Amplification: 1, RepresentationCost: representationCost(candidate.Representation)}
	risk := CandidateRisk{Tier: "endpoint-safe", AutomaticOK: true}
	for _, operation := range candidate.Operations {
		if _, blocked := excluded[operation.Family]; blocked {
			result.Reason = fmt.Sprintf("operator %q excluded by behavioral evidence", operation.Family)
			return result
		}
		if operation.Family == detector.OperatorSafeFakeProfile {
			if !limits.AllowSafeFake {
				result.Reason = "safe fake operator disabled by policy"
				return result
			}
			if !containsCandidate(req.SafeFakeProfileIDs, operation.Params["profile_id"]) {
				result.Reason = "safe fake profile is not in the bounded validated request set"
				return result
			}
		}
		if operation.Family == detector.OperatorBoundedDisorder && !limits.AllowDisorder {
			result.Reason = "bounded disorder disabled by policy"
			return result
		}
		if operation.Family == detector.OperatorPerFlowJitter && !limits.AllowJitter {
			result.Reason = "jitter disabled by policy"
			return result
		}
		if err := p.Grammar.ValidateOperation(operation, true); err != nil {
			result.Reason = err.Error()
			return result
		}
		definition, _ := p.Grammar.Operator(operation.Family)
		if !representationAllowed(candidate.Representation, definition.Representations) {
			result.Reason = fmt.Sprintf("operator %q incompatible with representation", operation.Family)
			return result
		}
		cost.Branches += definition.Branches
		cost.EstimatedPackets += definition.BasePackets
		cost.CPUUnits += definition.BaseCPUUnits
		cost.LatencyPenaltyMS += definition.BaseLatencyMS
		switch operation.Family {
		case detector.OperatorSafeDuplicateOriginal, detector.OperatorPrePadding, detector.OperatorPostPadding:
			cost.Amplification += 0.25
		case detector.OperatorSafeFakeProfile:
			cost.Amplification += 0.5
		}
	}
	if cost.Branches > maxBranches {
		result.Reason = "candidate branch count exceeds bound"
		return result
	}
	if cost.Amplification > maxAmplification {
		result.Reason = "candidate amplification exceeds bound"
		return result
	}
	result.Valid, result.Cost, result.Risk = true, cost, risk
	result.Reason = "finite grammar, action-bridge shape and behavioral constraints accepted"
	return result
}

func candidateActionBridgeShape(operations []CandidateOperation) string {
	fakeCount := 0
	disorderCount := 0
	structuralCount := 0
	transformCount := 0
	markers := map[string]struct{}{}
	for _, operation := range operations {
		switch operation.Family {
		case detector.OperatorTCPSplit, detector.OperatorTLSRecordSplit, detector.OperatorBoundedDisorder:
			structuralCount++
			if operation.Family == detector.OperatorBoundedDisorder {
				disorderCount++
			}
			marker := operation.Params["marker"]
			if marker != "" {
				if _, duplicate := markers[marker]; duplicate {
					return "candidate contains duplicate structural marker boundaries"
				}
				markers[marker] = struct{}{}
			}
		case detector.OperatorSafeFakeProfile:
			fakeCount++
		case detector.OperatorSafeDuplicateOriginal, detector.OperatorPerFlowJitter, detector.OperatorPrePadding, detector.OperatorPostPadding:
			transformCount++
		}
	}
	if fakeCount > 1 || (fakeCount == 1 && (structuralCount > 0 || transformCount > 0)) {
		return "safe fake profile must remain a standalone structural plan in grammar v1"
	}
	if disorderCount > 1 {
		return "candidate contains multiple disorder operators unsupported by the existing ActionPlanner bridge"
	}
	return ""
}

func (p SynthesisPlanner) Plan(req SynthesisRequest, prior detector.DiscoverySearchPrior, existingCanonicalHashes map[string]struct{}) (SynthesisPlanResult, error) {
	result := SynthesisPlanResult{RequestID: req.RequestID, Rejected: map[string]string{}}
	if err := p.Grammar.Validate(); err != nil {
		return result, err
	}
	if !req.Valid(req.RequestedAt) {
		return result, errors.New("invalid synthesis request")
	}
	if !prior.Valid() || prior.Scope != req.Scope || prior.ProfileID != req.BlockingProfileID || prior.BehavioralEvidenceID != req.BehavioralEvidenceID {
		return result, errors.New("exact-scope behavioral DDI prior required")
	}
	limits := req.Limits.normalized()
	if limits.MaxCandidates == 0 || limits.MaxGenerations == 0 {
		return result, errors.New("synthesis bounds required")
	}

	seen := make(map[string]struct{}, len(existingCanonicalHashes)+int(limits.MaxCandidates))
	for h := range existingCanonicalHashes {
		seen[h] = struct{}{}
	}
	failed := make(map[string]struct{}, len(req.FailedCandidateIDs))
	for _, id := range req.FailedCandidateIDs {
		failed[id] = struct{}{}
	}

	seedOps := p.seedOperations(prior, limits, req.SafeFakeProfileIDs)
	trigger := CandidateTrigger{Phase: "complete-reassembled-clienthello", Marker: "host-start"}
	generation := uint8(0)
	frontier := make([]SynthesizedCandidatePlan, 0, len(seedOps))
	for _, op := range seedOps {
		candidate, err := newSynthesizedCandidate(req, generation, nil, trigger, []CandidateOperation{op}, action.RepresentationNormalTCP, []string{"current-action-authorization", "complete-clienthello"}, CandidateCost{}, CandidateRisk{}, []string{"behavioral-seed"}, req.RequestedAt)
		if err != nil {
			return result, err
		}
		validation := p.ValidateCandidate(req, prior, candidate)
		if !validation.Valid {
			result.Rejected[candidate.CandidateID] = validation.Reason
			continue
		}
		candidate.StaticCost, candidate.Risk = validation.Cost, validation.Risk
		if _, duplicate := seen[candidate.CanonicalHash]; duplicate {
			result.Rejected[candidate.CandidateID] = "canonical duplicate"
			continue
		}
		if _, wasFailed := failed[candidate.CandidateID]; wasFailed {
			result.Rejected[candidate.CandidateID] = "candidate already failed in current context"
			continue
		}
		seen[candidate.CanonicalHash] = struct{}{}
		frontier = append(frontier, candidate)
	}
	orderCandidates(frontier, prior, req.DeterministicSeed)
	appendCandidatesBounded(&result.Candidates, frontier, int(limits.MaxCandidates))

	for generation = 1; generation < limits.MaxGenerations && len(result.Candidates) < int(limits.MaxCandidates); generation++ {
		parents := append([]SynthesizedCandidatePlan(nil), frontier...)
		if len(parents) == 0 {
			break
		}
		generationLimits := limits
		remaining := int(limits.MaxCandidates) - len(result.Candidates)
		if remaining < int(generationLimits.MaxCandidates) {
			generationLimits.MaxCandidates = uint16(remaining)
		}
		next, err := p.evolveGeneration(req, prior, parents, seedOps, generation, seen, failed, result.Rejected, generationLimits)
		if err != nil {
			return result, err
		}
		orderCandidates(next, prior, req.DeterministicSeed+int64(generation))
		appendCandidatesBounded(&result.Candidates, next, int(limits.MaxCandidates))
		frontier = next
	}
	result.Exhausted = len(result.Candidates) >= int(limits.MaxCandidates) || generation >= limits.MaxGenerations
	if len(result.Candidates) == 0 {
		result.Reason = "no statically valid novel candidates within bounded grammar"
	} else {
		result.Reason = "bounded deterministic mutation/crossover candidates ready for existing Discovery evaluation"
	}
	return result, nil
}

func (p SynthesisPlanner) seedOperations(prior detector.DiscoverySearchPrior, limits SynthesisLimits, safeFakeProfileIDs []string) []CandidateOperation {
	supported := operatorSet(prior.SupportedOperators)
	penalized := operatorSet(prior.PenalizedOperators)
	excluded := operatorSet(prior.ExcludedOperators)
	type ranked struct {
		op     CandidateOperation
		rank   int
		family string
	}
	items := make([]ranked, 0)
	for _, definition := range p.Grammar.Operators {
		if !definition.AutomaticSafe || definition.Compiler == "unavailable" {
			continue
		}
		if _, blocked := excluded[definition.Family]; blocked {
			continue
		}
		if definition.Family == detector.OperatorBoundedDisorder && !limits.AllowDisorder {
			continue
		}
		if definition.Family == detector.OperatorPerFlowJitter && !limits.AllowJitter {
			continue
		}
		rank := 1
		if _, ok := supported[definition.Family]; ok {
			rank = 0
		}
		if _, ok := penalized[definition.Family]; ok {
			rank = 2
		}

		if definition.Family == detector.OperatorSafeFakeProfile {
			if !limits.AllowSafeFake {
				continue
			}
			for _, profileID := range stableUniqueStrings(safeFakeProfileIDs) {
				params := defaultOperationParams(definition)
				params["profile_id"] = profileID
				items = append(items, ranked{
					op:     CandidateOperation{Family: definition.Family, Params: params},
					rank:   rank,
					family: string(definition.Family) + "/" + profileID,
				})
			}
			continue
		}

		items = append(items, ranked{
			op:     CandidateOperation{Family: definition.Family, Params: defaultOperationParams(definition)},
			rank:   rank,
			family: string(definition.Family),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].rank != items[j].rank {
			return items[i].rank < items[j].rank
		}
		return items[i].family < items[j].family
	})
	out := make([]CandidateOperation, 0, len(items))
	for _, item := range items {
		out = append(out, item.op)
	}
	return out
}

func defaultOperationParams(definition OperatorDefinition) map[string]string {
	params := make(map[string]string, len(definition.ParameterDomain)+len(definition.ExternalParams))
	keys := make([]string, 0, len(definition.ParameterDomain))
	for key := range definition.ParameterDomain {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		params[key] = definition.ParameterDomain[key][0]
	}
	return params
}

func operatorSet(in []detector.StrategyOperatorFamily) map[detector.StrategyOperatorFamily]struct{} {
	out := make(map[detector.StrategyOperatorFamily]struct{}, len(in))
	for _, op := range in {
		out[op] = struct{}{}
	}
	return out
}

func representationCost(r action.PacketRepresentation) string {
	switch r {
	case action.RepresentationGSOSafe:
		return "gso-safe"
	case action.RepresentationNormalTCP:
		return "normal-tcp"
	default:
		return "any"
	}
}

func appendCandidatesBounded(dst *[]SynthesizedCandidatePlan, src []SynthesizedCandidatePlan, max int) {
	for _, c := range src {
		if len(*dst) >= max {
			return
		}
		*dst = append(*dst, c)
	}
}

func orderCandidates(candidates []SynthesizedCandidatePlan, prior detector.DiscoverySearchPrior, seed int64) {
	supported := operatorSet(prior.SupportedOperators)
	penalized := operatorSet(prior.PenalizedOperators)
	score := func(c SynthesizedCandidatePlan) int {
		s := int(c.StaticCost.Actions)*100 + int(c.StaticCost.LatencyPenaltyMS) + int(c.StaticCost.CPUUnits)
		for _, op := range c.Operations {
			if _, ok := supported[op.Family]; ok {
				s -= 25
			}
			if _, ok := penalized[op.Family]; ok {
				s += 25
			}
		}
		return s
	}
	tie := func(id string) uint64 {
		h := fnv.New64a()
		_, _ = h.Write([]byte(fmt.Sprintf("%d:%s", seed, id)))
		return h.Sum64()
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		si, sj := score(candidates[i]), score(candidates[j])
		if si != sj {
			return si < sj
		}
		ti, tj := tie(candidates[i].CandidateID), tie(candidates[j].CandidateID)
		if ti != tj {
			return ti < tj
		}
		return candidates[i].CandidateID < candidates[j].CandidateID
	})
}
