package fieldtest

import "github.com/daniellavrushin/b4/validation"

type PromotionVerdict string

const (
	PromotionPass    PromotionVerdict = "PASS"
	PromotionBlocked PromotionVerdict = "BLOCKED_TARGET_VALIDATION"
	PromotionFail    PromotionVerdict = "FAIL"
)

type PromotionInput struct {
	Target                  CandidateMetrics
	Controls                AuthorizationAudit
	Capabilities            Capabilities
	RepresentationOK, RSTOK bool
	SafetyHash              string
	ConfigGeneration        uint64
	ReportOnly              bool
	Canary                  CanaryResult
	// GateEvaluation carries the structured hard-gate result (FB-03).
	// When non-nil, any violation or missing applicable gate blocks
	// promotion (v2 §0.6.3/§0.6.4).
	GateEvaluation *validation.GateEvaluation
}

func Promote(i PromotionInput, g CandidateGate) PromotionVerdict {
	if i.SafetyHash == "" || i.ConfigGeneration == 0 || !Eligible(i.Target, g) || !i.Controls.Clean() || !i.RepresentationOK || !i.RSTOK {
		return PromotionBlocked
	}
	if i.GateEvaluation != nil {
		switch i.GateEvaluation.Verdict {
		case validation.GateFail:
			return PromotionFail
		case validation.GateBlocked, validation.GateStale, validation.GateNotRun:
			return PromotionBlocked
		}
	}
	if i.ReportOnly {
		return PromotionPass
	}
	if !i.Canary.Promoted && !i.Canary.RolledBack {
		return PromotionBlocked
	}
	return PromotionPass
}
