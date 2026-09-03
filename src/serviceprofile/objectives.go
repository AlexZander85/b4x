package serviceprofile

import "github.com/daniellavrushin/b4/serviceprofile/schema"

type Objective struct {
	Startup, UICompletion, Media, VoiceGateway, TransportConnectivity, ProxyHandshake, Goodput, FailoverSeconds float64
	ResourceGate                                                                                                string
}
type ComponentObjective struct {
	ComponentID string
	Objective   Objective
	Delivery    schema.DeliveryMode
}

func ValidateObjective(o ComponentObjective) bool {
	if o.ComponentID == "" || o.Delivery == "" {
		return false
	}
	if o.Objective.FailoverSeconds < 0 || o.Objective.Goodput < 0 {
		return false
	}
	return o.Delivery != schema.RouterTunnel || o.Objective.TransportConnectivity > 0
}
