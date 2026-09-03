package fieldtest

import (
	"errors"

	"github.com/daniellavrushin/b4/validation"
)

type CanaryMode string

const (
	ReportOnly CanaryMode = "report-only"
	CanaryAuto CanaryMode = "canary-auto"
	FullAuto   CanaryMode = "full-auto"
)

type CanaryRequest struct {
	CandidateID       string
	ClientIDs         []string
	FlowPercent       int
	DurationSec       int
	AutomaticRollback bool
	Mode              CanaryMode
}
type CanaryResult struct {
	CandidateID                   string
	Started, RolledBack, Promoted bool
	Reason                        string
}

func ValidateCanary(r CanaryRequest) error {
	if r.CandidateID == "" || len(r.ClientIDs) == 0 || r.FlowPercent < 1 || r.FlowPercent > 100 || r.DurationSec <= 0 {
		return errors.New("invalid canary scope")
	}
	if r.Mode == FullAuto && !r.AutomaticRollback {
		return errors.New("full auto requires rollback")
	}
	return nil
}

// CanaryEligible reports whether a hard-gate evaluation admits a canary
// rollout: only an unconditional PASS is eligible. BLOCKED/STALE/NOT_RUN
// (missing producers, stale generation) and FAIL must block the rollout
// (v2 §0.6.3). A nil evaluation is treated as eligible (no gates wired).
func CanaryEligible(eval *validation.GateEvaluation) bool {
	if eval == nil {
		return true
	}
	return eval.Verdict == validation.GatePass
}
