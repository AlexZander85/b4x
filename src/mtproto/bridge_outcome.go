package mtproto

type BridgeDisposition string

const (
	BridgeHandled  BridgeDisposition = "handled"
	BridgeFailOpen BridgeDisposition = "fail-open"
	BridgeDrop     BridgeDisposition = "drop"
	BridgePending  BridgeDisposition = "pending"
)

type BridgeReason string

const (
	ReasonHandshakeAccepted BridgeReason = "handshake-accepted"
	ReasonZeroByte          BridgeReason = "zero-byte"
	ReasonPartialPrefix     BridgeReason = "partial-prefix"
	ReasonDecodeFailed      BridgeReason = "decode-failed"
	ReasonDialFailed        BridgeReason = "dial-failed"
	ReasonOverflow          BridgeReason = "overflow"
	ReasonShutdown          BridgeReason = "shutdown"
)

type BridgeOutcome struct {
	Disposition         BridgeDisposition
	Reason              BridgeReason
	BytesRead           int
	Prefix              []byte
	OriginalDestination string
	UpstreamRoute       string
}

func (o BridgeOutcome) Valid() bool {
	if o.Disposition == BridgeFailOpen && len(o.Prefix) == 0 && o.BytesRead > 0 {
		return false
	}
	return o.Disposition != "" && o.Reason != ""
}
func LegacyBridgeOutcome(handled bool, conn netConnCompat, reason BridgeReason) BridgeOutcome {
	if handled {
		return BridgeOutcome{Disposition: BridgeHandled, Reason: reason}
	}
	o := BridgeOutcome{Disposition: BridgeFailOpen, Reason: reason}
	if conn != nil {
		o.Prefix = conn.Prefix()
	}
	return o
}

type netConnCompat interface{ Prefix() []byte }
type PrefixSnapshot struct{ Data []byte }

func (s PrefixSnapshot) Prefix() []byte { return append([]byte(nil), s.Data...) }
