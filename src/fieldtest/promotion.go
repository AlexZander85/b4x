package fieldtest

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
}

func Promote(i PromotionInput, g CandidateGate) PromotionVerdict {
	if i.SafetyHash == "" || i.ConfigGeneration == 0 || !Eligible(i.Target, g) || !i.Controls.Clean() || !i.RepresentationOK || !i.RSTOK {
		return PromotionBlocked
	}
	if i.ReportOnly {
		return PromotionPass
	}
	if !i.Canary.Promoted && !i.Canary.RolledBack {
		return PromotionBlocked
	}
	return PromotionPass
}
