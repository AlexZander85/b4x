package warp

import "errors"

type TransportAuthorization struct {
	FlowID, ServiceProfile, ClientKey, DestinationHash string
	RouteGeneration                                    uint64
	ConfigGeneration                                   uint64
	AllowForwarded                                     bool
	AllowControl                                       bool
	MSSClamp                                           int
	DNSBinding                                         string
}

func (a TransportAuthorization) Valid() bool {
	return a.FlowID != "" && a.ServiceProfile != "" && a.ClientKey != "" && a.DestinationHash != "" && a.RouteGeneration > 0 && a.ConfigGeneration > 0 && (a.AllowForwarded || a.AllowControl)
}
func RevokeOnNegativeEvidence(a *TransportAuthorization, flow string) error {
	if a == nil || !a.Valid() {
		return errors.New("invalid authorization")
	}
	if a.FlowID != flow {
		return errors.New("flow mismatch")
	}
	a.AllowForwarded = false
	a.AllowControl = false
	return nil
}

type RouteGeneration struct {
	ID     uint64
	Owner  string
	Active bool
}

func (g RouteGeneration) Valid() bool { return g.ID > 0 && g.Owner != "" }
