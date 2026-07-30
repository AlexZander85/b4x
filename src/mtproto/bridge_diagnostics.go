package mtproto

type BridgeMode string

const (
	BridgeBeginnerAuto BridgeMode = "beginner-auto"
	BridgeAdvanced     BridgeMode = "advanced"
)

type BridgeDiagnosticsOptions struct {
	Mode                                       BridgeMode
	SoftDeadlineMS, HardDeadlineMS, MaxPending int
}

func DefaultBridgeDiagnostics() BridgeDiagnosticsOptions {
	return BridgeDiagnosticsOptions{Mode: BridgeBeginnerAuto, SoftDeadlineMS: 5000, HardDeadlineMS: 30000, MaxPending: 128}
}

type BridgeTrace struct {
	Disposition   BridgeDisposition
	Reason        BridgeReason
	Pending       bool
	Route         BridgeRoute
	SecretPresent bool
}

func (t BridgeTrace) Redacted() BridgeTrace { t.SecretPresent = false; return t }

type BridgeStatusView struct {
	Mode        BridgeMode
	Pending     int
	Active      int
	LastReason  BridgeReason
	Explanation string
}
