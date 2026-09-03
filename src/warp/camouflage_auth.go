package warp

type TransportControlPurpose string

const (
	PurposeBaseControl TransportControlPurpose = "base-control"
	PurposeCamouflage  TransportControlPurpose = "camouflage"
	PurposeEstablished TransportControlPurpose = "established"
)

type TransportControlAuthorization struct {
	SocketID, FlowKey, EndpointHash, InstanceID string
	Purpose                                     TransportControlPurpose
	ProcessGeneration, ConfigGeneration         uint64
	ExpiresAt                                   int64
}

func (a TransportControlAuthorization) Valid(gen, cfg uint64) bool {
	return a.SocketID != "" && a.FlowKey != "" && a.EndpointHash != "" && a.InstanceID != "" && a.Purpose != "" && a.ProcessGeneration == gen && a.ConfigGeneration == cfg
}

type VerdictClass string

const (
	BypassVerdict      VerdictClass = "bypass"
	CamouflageVerdict  VerdictClass = "camouflage"
	EstablishedVerdict VerdictClass = "established"
)
