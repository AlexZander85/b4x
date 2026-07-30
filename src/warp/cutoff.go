package warp

type CutoffState string

const (
	CutoffPending     CutoffState = "pending"
	CutoffEstablished CutoffState = "established"
	CutoffFallback    CutoffState = "fallback"
)

type MasqueConnectedEvent struct {
	InstanceID, SessionID               string
	ProcessGeneration, ConfigGeneration uint64
	Success                             bool
	Sequence                            uint64
}
type CutoffMachine struct {
	InstanceID, SessionID               string
	ProcessGeneration, ConfigGeneration uint64
	State                               CutoffState
	LastSequence                        uint64
}

func (m *CutoffMachine) Apply(e MasqueConnectedEvent) bool {
	if m == nil || e.InstanceID != m.InstanceID || e.SessionID != m.SessionID || e.ProcessGeneration != m.ProcessGeneration || e.ConfigGeneration != m.ConfigGeneration || e.Sequence <= m.LastSequence {
		return false
	}
	m.LastSequence = e.Sequence
	if e.Success {
		m.State = CutoffEstablished
	} else {
		m.State = CutoffFallback
	}
	return true
}
func (m *CutoffMachine) HardFallback() {
	if m != nil && m.State == CutoffPending {
		m.State = CutoffFallback
	}
}
