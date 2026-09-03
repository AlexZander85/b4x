package fieldtest

type DetectorReleaseGate struct {
	TargetPlan, CleanBaseline, DNS, TLSHTTP, QUIC, L4, Dynamic, EvidenceGraph, BlockingProfile, DDIAdapter, DDISchema, DDIRevalidation, DDIHints, DDITarget, TelegramState, TelegramBudget, TelegramPrefix, TelegramAndroid, TelegramProduction bool
	Issue277, Issue278                                                                                                                                                                                                                          bool
	HardGateViolations                                                                                                                                                                                                                          []string
}

func (g DetectorReleaseGate) Verdicts() map[string]PromotionVerdict {
	out := map[string]PromotionVerdict{}
	if g.TargetPlan && g.CleanBaseline && len(g.HardGateViolations) == 0 {
		out["ABD_PRODUCTION_READY"] = PromotionPass
	} else {
		out["ABD_PRODUCTION_READY"] = PromotionBlocked
	}
	if g.DDIAdapter && g.DDISchema && g.DDIRevalidation && g.DDIHints && g.DDITarget {
		out["DDI_PRODUCTION_READY"] = PromotionPass
	} else {
		out["DDI_PRODUCTION_READY"] = PromotionBlocked
	}
	if g.TelegramState && g.TelegramBudget && g.TelegramPrefix && g.TelegramAndroid && g.TelegramProduction {
		out["TGB_PRODUCTION_READY"] = PromotionPass
	} else {
		out["TGB_PRODUCTION_READY"] = PromotionBlocked
	}
	if g.Issue277 {
		out["ISSUE_277_RESOLVED"] = PromotionPass
	} else {
		out["ISSUE_277_RESOLVED"] = PromotionBlocked
	}
	if g.Issue278 {
		out["ISSUE_278_RESOLVED"] = PromotionPass
	} else {
		out["ISSUE_278_RESOLVED"] = PromotionBlocked
	}
	return out
}
