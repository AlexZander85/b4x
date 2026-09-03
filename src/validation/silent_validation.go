package validation

type SilentValidation struct {
	Registry, Observe, Recommend, AutoCanary, Cohort, Suppressors, Controls, WARPRecursionGuard, FalsePositiveRollback, Cleanup bool
	HardGateViolations                                                                                                          []string
	EvidenceAgeSeconds                                                                                                          int64
}

func (s SilentValidation) Verdict(mode string) Verdict {
	if len(s.HardGateViolations) > 0 || !s.Registry || !s.Suppressors || !s.Controls || !s.Cleanup {
		return Blocked
	}
	switch mode {
	case "observe":
		if s.Observe {
			return Pass
		}
	case "recommend":
		if s.Observe && s.Recommend {
			return Pass
		}
	case "auto-canary":
		if s.Observe && s.Recommend && s.AutoCanary && s.FalsePositiveRollback && s.WARPRecursionGuard {
			return Pass
		}
	case "cohort":
		if s.Observe && s.Recommend && s.AutoCanary && s.Cohort && s.FalsePositiveRollback && s.WARPRecursionGuard {
			return Pass
		}
	}
	return Blocked
}
