package fieldtest

type RSTMode string

const (
	RSTObserve      RSTMode = "observe"
	RSTConservative RSTMode = "conservative"
	RSTAggressive   RSTMode = "aggressive"
)

type RSTSuite struct {
	Mode                RSTMode
	VisibilityComplete  bool
	SuppressionBudget   int
	RollbackReady       bool
	ReconnectRegression bool
	Actions             int
}

func (r RSTSuite) Valid() bool {
	if r.Mode == RSTAggressive {
		return false
	}
	if r.Mode == RSTObserve {
		return true
	}
	return r.VisibilityComplete && r.SuppressionBudget > 0 && r.RollbackReady && !r.ReconnectRegression && r.Actions <= r.SuppressionBudget
}
