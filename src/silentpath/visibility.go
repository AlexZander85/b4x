package silentpath

// CapabilitySnapshot is an immutable view of the capture path at assessment
// time. It deliberately does not retain a live PPE/NFQUEUE pointer.
type CapabilitySnapshot struct {
	IncomingComplete bool
	OutgoingComplete bool
	QueueHealthy     bool
	GSOParityProven  bool
	OffloadProven    bool
}

func (s CapabilitySnapshot) Complete() bool {
	return s.IncomingComplete && s.OutgoingComplete && s.QueueHealthy && s.GSOParityProven && s.OffloadProven
}

// EffectiveMode never promotes a requested active mode beyond observation
// unless all five required visibility proofs are current.
func EffectiveMode(configured string, snapshot CapabilitySnapshot) (string, string) {
	if configured == "off" {
		return "off", "disabled"
	}
	if configured == "observe" || configured == "" {
		return "observe", "configured_observe"
	}
	if !snapshot.Complete() {
		return "observe", "visibility_incomplete"
	}
	return configured, "complete_visibility"
}

type Milestone string

const (
	MilestoneSYN             Milestone = "syn"
	MilestoneSYNACK          Milestone = "syn_ack"
	MilestoneClientHello     Milestone = "client_hello_complete"
	MilestoneServerHello     Milestone = "server_hello"
	MilestoneApplicationData Milestone = "first_application_data"
	MilestoneFIN             Milestone = "fin"
	MilestoneRST             Milestone = "rst"
	MilestoneTLSAlert        Milestone = "tls_alert"
)

type Milestones struct{ SYN, SYNACK, ClientHelloComplete, ServerHello, ApplicationData, FIN, RST, TLSAlert bool }

func (m *Milestones) Observe(event Milestone) {
	switch event {
	case MilestoneSYN:
		m.SYN = true
	case MilestoneSYNACK:
		m.SYNACK = true
	case MilestoneClientHello:
		m.ClientHelloComplete = true
	case MilestoneServerHello:
		m.ServerHello = true
	case MilestoneApplicationData:
		m.ApplicationData = true
	case MilestoneFIN:
		m.FIN = true
	case MilestoneRST:
		m.RST = true
	case MilestoneTLSAlert:
		m.TLSAlert = true
	}
}
