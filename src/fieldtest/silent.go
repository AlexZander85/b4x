package fieldtest

type SilentMode string

const (
	SilentObserve    SilentMode = "observe"
	SilentRecommend  SilentMode = "recommend"
	SilentAutoCanary SilentMode = "auto-canary"
)

type ProgressSample struct {
	ScopeHash, FlowID                          string
	UniqueBytesIn, UniqueBytesOut              uint64
	PacketsIn, PacketsOut                      uint64
	Milestone                                  string
	FastParallel, HLS, Prefetch, RecentSuccess bool
}

func (p ProgressSample) Valid() bool {
	return p.ScopeHash != "" && p.FlowID != "" && (!p.FastParallel && !p.HLS && !p.Prefetch && !p.RecentSuccess)
}

type SilentObservation struct {
	Mode                                                   SilentMode
	Samples                                                []ProgressSample
	IndependentFamilies                                    int
	VisibilityComplete, DifferentialProof, ControlsHealthy bool
	Suppressed                                             int
}

func SuppressedPattern(p ProgressSample) bool {
	return p.FastParallel || p.HLS || p.Prefetch || p.RecentSuccess
}

func (o SilentObservation) Ready() bool {
	return len(o.Samples) > 0 && o.IndependentFamilies >= 2 && o.VisibilityComplete && o.ControlsHealthy
}

type FalsePositiveResult struct {
	ActionID, LeaseID                            string
	RolledBack, ControlsRecovered, BudgetCharged bool
}

func (r FalsePositiveResult) Safe() bool {
	return r.ActionID != "" && r.LeaseID != "" && r.RolledBack && r.ControlsRecovered
}

type DifferentialProof struct {
	ID, ScopeHash, BaselineID, CandidateID               string
	DirectFailed, CandidateSucceeded, ControlsUnaffected bool
	ConfigGen                                            uint64
}

func (p DifferentialProof) Valid() bool {
	return p.ID != "" && p.ScopeHash != "" && p.BaselineID != "" && p.CandidateID != "" && p.DirectFailed && p.CandidateSucceeded && p.ControlsUnaffected && p.ConfigGen > 0
}

type RecoveryLongRun struct {
	Observation               SilentObservation
	Proofs                    []DifferentialProof
	FalsePositives            []FalsePositiveResult
	LeaseCount, RollbackCount int
	Promotion                 PromotionVerdict
}

func (r RecoveryLongRun) Ready() bool {
	if !r.Observation.Ready() || r.Observation.Mode == SilentObserve && r.Promotion == PromotionPass {
		return false
	}
	for _, p := range r.Proofs {
		if !p.Valid() {
			return false
		}
	}
	for _, f := range r.FalsePositives {
		if !f.Safe() {
			return false
		}
	}
	return r.LeaseCount >= r.RollbackCount
}
