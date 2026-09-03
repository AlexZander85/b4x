package serviceprofile

import "errors"

type TransportBinding struct {
	ID, Kind, ComponentID, Scope, SecretRef string
	RouterScoped                            bool
	ClientConfigured                        bool
}
type ClientSetupAction struct {
	ID, Kind, Artifact string
	SecretRef          string
}
type TransportProbe struct {
	ID, Path  string
	Healthy   bool
	LatencyMS int
}

func ValidateTransportBinding(b TransportBinding) error {
	if b.ID == "" || b.Kind == "" || b.ComponentID == "" || b.Scope == "" {
		return errors.New("transport binding requires scope")
	}
	if b.RouterScoped && b.Scope == "global" {
		return errors.New("global router transport forbidden")
	}
	if b.SecretRef != "" && len(b.SecretRef) > 128 {
		return errors.New("secret reference too long")
	}
	return nil
}
