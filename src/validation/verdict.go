package validation

type Verdict string

const (
	Pass                   Verdict = "PASS"
	PassWithLimitations    Verdict = "PASS_WITH_LIMITATIONS"
	Fail                   Verdict = "FAIL"
	ErrorVerdict           Verdict = "ERROR"
	Blocked                Verdict = "BLOCKED_TARGET_VALIDATION"
	BlockedCapability      Verdict = "BLOCKED_CAPABILITY"
	BlockedMissingProducer Verdict = "BLOCKED_MISSING_PRODUCER"
	BlockedMissingArtifact Verdict = "BLOCKED_MISSING_ARTIFACT"
	BlockedTraceSchema     Verdict = "BLOCKED_TRACE_SCHEMA"
	BlockedTraceRuntime    Verdict = "BLOCKED_TRACE_RUNTIME_MISMATCH"
	NotApplicable          Verdict = "NOT_APPLICABLE"
)

type StageResult struct {
	Stage              string   `json:"stage"`
	Verdict            Verdict  `json:"verdict"`
	Requirements       []string `json:"requirements,omitempty"`
	Tests              []string `json:"tests,omitempty"`
	Artifacts          []string `json:"artifacts,omitempty"`
	Limitations        []string `json:"limitations,omitempty"`
	Dependencies       []string `json:"dependencies,omitempty"`
	HardGateViolations []string `json:"hard_gate_violations,omitempty"`
}

func Aggregate(results []StageResult) Verdict {
	if len(results) == 0 {
		return Blocked
	}
	limited := false
	for _, r := range results {
		if DetectFalsePass(r) {
			return Blocked
		}
		if len(r.HardGateViolations) > 0 {
			return Blocked
		}
		switch r.Verdict {
		case Pass:
		case PassWithLimitations:
			limited = true
		case Fail, ErrorVerdict:
			return Fail
		case NotApplicable:
		default:
			return Blocked
		}
	}
	if limited {
		return PassWithLimitations
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
