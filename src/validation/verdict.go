package validation

type Verdict string

const (
	Pass                Verdict = "PASS"
	PassWithLimitations Verdict = "PASS_WITH_LIMITATIONS"
	Fail                Verdict = "FAIL"
	Blocked             Verdict = "BLOCKED_TARGET_VALIDATION"
	NotApplicable       Verdict = "NOT_APPLICABLE"
)

type StageResult struct {
	Stage                                       string
	Verdict                                     Verdict
	Requirements, Tests, Artifacts, Limitations []string
	Dependencies                                []string
	HardGateViolations                          []string
}

func Aggregate(results []StageResult) Verdict {
	if len(results) == 0 {
		return Blocked
	}
	for _, r := range results {
		if r.Verdict == Fail || r.Verdict == Blocked {
			return Blocked
		}
		if len(r.HardGateViolations) > 0 {
			return Blocked
		}
		if r.Verdict == PassWithLimitations {
			return PassWithLimitations
		}
	}
	return Pass
}
func DetectFalsePass(r StageResult) bool {
	if r.Verdict == Pass && (len(r.Requirements) == 0 || len(r.Tests) == 0 || len(r.Artifacts) == 0 || len(r.HardGateViolations) > 0) {
		return true
	}
	return false
}
func DependencyBlocked(r StageResult, by map[string]Verdict) bool {
	for _, d := range r.Dependencies {
		if v := by[d]; v != Pass && v != PassWithLimitations {
			return true
		}
	}
	return false
}
