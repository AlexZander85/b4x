package classifier

import "fmt"

func (d ClassificationDecision) CanClassify(t ConfidenceThresholds) bool {
	return d.Selected != nil && d.Confidence >= t.Classify && d.Phase >= PhaseResolved
}

func (d ClassificationDecision) CanMutate(t ConfidenceThresholds) bool {
	return d.Selected != nil && d.Confidence >= t.Mutate && (d.Phase == PhaseResolved || d.Phase == PhaseFinal) && !d.Ambiguous()
}

func (d ClassificationDecision) CanDestructivelyMutate(t ConfidenceThresholds) bool {
	return d.Selected != nil && d.Confidence >= t.Destructive && d.Phase == PhaseFinal && d.Selected.DomainEvidence && !d.ECHPresent
}

func (d ClassificationDecision) CanProxyFallback(t ConfidenceThresholds) bool {
	threshold := t.ProxyFallback
	if threshold < t.Mutate {
		threshold = t.Mutate
	}
	return d.Selected == nil || d.Confidence < threshold || d.Phase == PhaseAmbiguous
}

func (d ClassificationDecision) Ambiguous() bool { return d.Phase == PhaseAmbiguous }

func Decide(ctx DecisionContext, input []Evidence, thresholds ConfidenceThresholds) ClassificationDecision {
	if thresholds == (ConfidenceThresholds{}) {
		thresholds = DefaultConfidenceThresholds
	}
	decision := ClassificationDecision{
		Phase:       PhaseInspecting,
		Candidates:  make([]Evidence, 0, len(input)),
		FlowKey:     ctx.FlowKey,
		TLSMetadata: ctx.TLSMetadata,
		ConfigGen:   ctx.ConfigGen,
	}

	for _, original := range input {
		e := NormalizeEvidence(original)
		decision.Candidates = append(decision.Candidates, e)
		if e.ECHRelated {
			decision.ECHPresent = true
		}
	}
	sortEvidence(decision.Candidates)

	valid := make([]Evidence, 0, len(input))
	for _, e := range decision.Candidates {
		if ValidForContext(e, ctx) {
			valid = append(valid, e)
		}
	}
	if len(valid) == 0 {
		if ctx.InputIncomplete || decision.ECHPresent {
			if decision.ECHPresent {
				decision.Phase = PhasePartial
				decision.Reason = "ECH present without eligible clear hostname evidence"
			} else {
				decision.Phase = PhaseInspecting
				decision.Reason = "awaiting eligible evidence"
			}
			return decision
		}
		decision.Phase = PhaseFinal
		decision.Final = true
		decision.Reason = "no eligible evidence"
		return decision
	}

	top := valid[0]
	decision.Confidence = top.Confidence
	if len(valid) > 1 {
		second := valid[1]
		if top.SetID != second.SetID && candidateStrength(top, second) {
			if !(isClearSNI(top) && (second.Source == EvidenceDNSAnswer || second.Source == EvidenceDNSHTTPS)) {
				decision.Phase = PhaseAmbiguous
				decision.Reason = "multiple candidates at equal evidence strength"
				return decision
			}
		}
		if isClearSNI(top) && (second.Source == EvidenceDNSAnswer || second.Source == EvidenceDNSHTTPS) && top.Domain != second.Domain {
			decision.Reason = "clear SNI overrides conflicting DNS evidence"
		}
	}

	selected := top
	decision.Selected = &selected
	if decision.Reason == "" {
		decision.Reason = fmt.Sprintf("selected %s evidence", top.Source)
	}
	if decision.ECHPresent && !isClearSNI(top) {
		decision.Phase = PhaseResolved
		decision.Final = false
		decision.Reason += "; ECH fallback remains non-final"
		return decision
	}
	if top.Confidence < thresholds.Classify {
		decision.Phase = PhaseResolved
		decision.Final = false
		decision.Reason += "; confidence below classification threshold"
		return decision
	}
	if ctx.InputIncomplete {
		decision.Phase = PhaseResolved
		decision.Final = false
		decision.Reason += "; input remains incomplete"
		return decision
	}
	decision.Phase = PhaseFinal
	decision.Final = true
	return decision
}
