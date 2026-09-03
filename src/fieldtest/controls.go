package fieldtest

type FlowRole string

const (
	TargetRole     FlowRole = "target"
	ControlRole    FlowRole = "control"
	BackgroundRole FlowRole = "background"
)

type ControlScenario struct {
	AppID, ScenarioID string
	Role              FlowRole
	UIRequired        bool
	NetworkOnly       bool
	Markers           []string
}
type ControlRun struct {
	Scenarios       []ControlScenario
	Concurrent      bool
	Baseline        bool
	CandidateID     string
	PrivacyRedacted bool
}

func (r ControlRun) Valid() bool {
	if !r.PrivacyRedacted || len(r.Scenarios) == 0 {
		return false
	}
	for _, s := range r.Scenarios {
		if s.Role != ControlRole || s.AppID == "" || s.ScenarioID == "" {
			return false
		}
	}
	return true
}
