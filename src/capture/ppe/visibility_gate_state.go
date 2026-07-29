package ppe

import "strings"

// EnsureRequired starts or preserves a generation-bound proof requirement. A
// complete proof for the same generation is retained across periodic asserts.
func (g *VisibilityGate) EnsureRequired(generation, reason string) CaptureVisibilitySnapshot {
	if g == nil {
		return CaptureVisibilitySnapshot{}
	}
	current := g.Snapshot()
	generation = strings.TrimSpace(generation)
	if current.Enforced && current.Generation == generation {
		return current
	}
	return g.publish(CaptureVisibilitySnapshot{
		Mode:       VisibilityUnknown,
		Enforced:   true,
		Generation: generation,
		Reason:     cleanVisibilityReason(reason, "controlled bidirectional visibility proof is required"),
	})
}

func (g *VisibilityGate) PublishSelfTest(result CaptureVisibilityResult) CaptureVisibilitySnapshot {
	return g.PublishSelfTestForGeneration(g.Snapshot().Generation, result)
}

func (g *VisibilityGate) PublishSelfTestForGeneration(generation string, result CaptureVisibilityResult) CaptureVisibilitySnapshot {
	if g == nil {
		return CaptureVisibilitySnapshot{}
	}
	mode := VisibilityUnknown
	reason := "controlled visibility test was inconclusive"
	switch result.Verdict {
	case VerdictPASS:
		if result.ProductionReady {
			mode = VisibilityComplete
			reason = "controlled A/B test proved bidirectional capture visibility"
		}
	case VerdictPASSWithLimitations:
		reason = "bidirectional packets were visible but A/B did not prove offload exclusion"
	case VerdictFAIL:
		mode = VisibilityIncomplete
		if result.OutgoingFirstPayloadSeen && result.OutgoingSecondRangeSeen && result.OutgoingRetransSeen && !result.IncomingProgressSeen {
			mode = VisibilityOutgoingOnly
		}
		reason = cleanVisibilityReason(result.FailureStage, "controlled visibility test failed")
	case VerdictUNSUPPORTED:
		reason = "PPE visibility capability is unsupported"
	case VerdictINCONCLUSIVE:
		reason = cleanVisibilityReason(result.FailureStage, reason)
	}
	return g.publish(CaptureVisibilitySnapshot{
		Mode:        mode,
		Enforced:    true,
		Generation:  strings.TrimSpace(generation),
		LastVerdict: result.Verdict,
		Reason:      reason,
	})
}

func (g *VisibilityGate) Invalidate(generation, reason string) CaptureVisibilitySnapshot {
	if g == nil {
		return CaptureVisibilitySnapshot{}
	}
	return g.publish(CaptureVisibilitySnapshot{
		Mode:       VisibilityUnknown,
		Enforced:   true,
		Generation: strings.TrimSpace(generation),
		Reason:     cleanVisibilityReason(reason, "capture visibility requires revalidation"),
	})
}

func (g *VisibilityGate) DisableRequirement(reason string) CaptureVisibilitySnapshot {
	if g == nil {
		return CaptureVisibilitySnapshot{}
	}
	return g.publish(CaptureVisibilitySnapshot{
		Mode:     VisibilityComplete,
		Enforced: false,
		Reason:   cleanVisibilityReason(reason, "PPE visibility proof is not required"),
	})
}

func (g *VisibilityGate) Degrade(generation, reason string) CaptureVisibilitySnapshot {
	if g == nil {
		return CaptureVisibilitySnapshot{}
	}
	return g.publish(CaptureVisibilitySnapshot{
		Mode:       VisibilityIncomplete,
		Enforced:   true,
		Generation: strings.TrimSpace(generation),
		Reason:     cleanVisibilityReason(reason, "capture visibility degraded"),
	})
}
