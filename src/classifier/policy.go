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

// CanUseHostMarkers is intentionally stricter than ordinary classification.
// DNS and QUIC can resolve an ECH flow to a set, but neither proves that a
// clear host marker is present in the TCP stream. ECH outer names are not
// treated as an inner clear hostname for marker-based actions.
func (d ClassificationDecision) CanUseHostMarkers() bool {
	return d.Selected != nil && !d.ECHPresent && isClearSNI(*d.Selected)
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
		Phase:            PhaseInspecting,
		Candidates:       make([]Evidence, 0, len(input)),
		Conflicts:        make([]EvidenceConflict, 0, len(input)),
		FlowKey:          ctx.FlowKey,
		TLSMetadata:      ctx.TLSMetadata,
		ConfigGen:        ctx.ConfigGen,
		DomainOnlyMode:   normalizeDomainOnlyMode(ctx.DomainOnlyMode),
		DomainOnlyResult: "not-applicable",
	}

	for _, original := range input {
		e := NormalizeEvidence(original)
		decision.Candidates = append(decision.Candidates, e)
		if e.ECHRelated {
			decision.ECHPresent = true
		}
	}
	decision.ECHPresent = decision.ECHPresent || ctx.TLSMetadata.ECHPresent
	sortEvidence(decision.Candidates)

	valid := make([]Evidence, 0, len(input))
	domainFiltered := false
	for _, e := range decision.Candidates {
		if !ValidForContext(e, ctx) {
			continue
		}
		allowed, result := domainOnlyEvidenceAllowed(ctx, e, thresholds)
		if ctx.DomainOnlySet != nil && ctx.DomainOnlySet(e.SetID) {
			decision.DomainOnlyApplied = true
			if decision.DomainOnlyResult == "not-applicable" || allowed {
				decision.DomainOnlyResult = result
			}
		}
		if !allowed {
			domainFiltered = true
			continue
		}
		valid = append(valid, e)
	}
	if decision.DomainOnlyApplied && decision.DomainOnlyResult == "not-applicable" {
		decision.DomainOnlyResult = "allowed"
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
			if domainFiltered {
				decision.Reason += "; DomainOnly filtered ineligible evidence"
			}
			return decision
		}
		decision.Phase = PhaseFinal
		decision.Final = true
		decision.Reason = "no eligible evidence"
		if domainFiltered {
			decision.Reason += "; DomainOnly filtered ineligible evidence"
		}
		return decision
	}

	top := valid[0]
	decision.Confidence = top.Confidence
	for _, candidate := range valid[1:] {
		if top.SetID == candidate.SetID || (top.Domain == "" && candidate.Domain == "") {
			continue
		}
		decision.Conflicts = append(decision.Conflicts, EvidenceConflict{
			Higher: top,
			Lower:  candidate,
			Reason: "different eligible set candidates for the same flow",
		})
	}
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
	decision.Corroborated = hasScopedCorroboration(top, valid[1:])
	if decision.Corroborated {
		decision.Confidence = minConfidence(100, int(decision.Confidence)+3)
	}
	if decision.Reason == "" {
		decision.Reason = fmt.Sprintf("selected %s evidence", top.Source)
	}
	if decision.Corroborated {
		decision.Reason += "; corroborated by independent scoped evidence"
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

func hasScopedCorroboration(selected Evidence, candidates []Evidence) bool {
	if !isECHScopedEvidence(selected) {
		return false
	}
	for _, candidate := range candidates {
		if candidate.SetID != selected.SetID || candidate.Source == selected.Source || !isECHScopedEvidence(candidate) {
			continue
		}
		if selected.DestinationIP.IsValid() && candidate.DestinationIP.IsValid() && selected.DestinationIP != candidate.DestinationIP {
			continue
		}
		return true
	}
	return false
}

func isECHScopedEvidence(e Evidence) bool {
	return e.Source == EvidenceQUICSNI || e.Source == EvidenceDNSAnswer || e.Source == EvidenceDNSHTTPS
}

func minConfidence(limit, value int) uint8 {
	if value > limit {
		value = limit
	}
	if value < 0 {
		value = 0
	}
	return uint8(value)
}

func normalizeDomainOnlyMode(mode DomainOnlyMode) DomainOnlyMode {
	switch mode {
	case DomainStrict, DomainScopedHints, DomainLegacy, DomainDisabled:
		return mode
	default:
		return DomainLegacy
	}
}

func domainOnlyEvidenceAllowed(ctx DecisionContext, e Evidence, thresholds ConfidenceThresholds) (bool, string) {
	if ctx.DomainOnlySet == nil || !ctx.DomainOnlySet(e.SetID) {
		return true, "not-applicable"
	}
	mode := normalizeDomainOnlyMode(ctx.DomainOnlyMode)
	if mode == DomainDisabled {
		return true, "disabled"
	}
	if !e.DomainEvidence {
		return false, "rejected:no-domain-evidence"
	}
	if EffectiveConfidence(e) < thresholds.Classify {
		return false, "rejected:below-confidence"
	}
	switch mode {
	case DomainStrict:
		switch e.Source {
		case EvidencePacketSNI, EvidenceReassembledSNI, EvidenceStaticHost:
			return true, "allowed:strict-domain-evidence"
		default:
			return false, "rejected:strict-source"
		}
	case DomainScopedHints:
		switch e.Source {
		case EvidencePacketSNI, EvidenceReassembledSNI, EvidenceQUICSNI, EvidenceDNSAnswer, EvidenceDNSHTTPS, EvidenceStaticHost:
			return true, "allowed:scoped-domain-evidence"
		default:
			return false, "rejected:scoped-source"
		}
	case DomainLegacy:
		switch e.Source {
		case EvidencePacketSNI, EvidenceReassembledSNI, EvidenceStaticHost:
			return true, "allowed:legacy-domain-evidence"
		default:
			return false, "rejected:legacy-source"
		}
	default:
		return false, "rejected:unsupported-mode"
	}
}
