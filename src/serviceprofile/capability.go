package serviceprofile

type Capability struct {
	Name, Version string
	Available     bool
	Reason        string
}
type CapabilityProjection struct {
	Capabilities          []Capability
	EffectiveDomainPolicy string
	IPCaptureOnly         bool
	NegativeControls      []string
	SideEffectScope       string
	MigrationWarnings     []string
}

func (p CapabilityProjection) AllowsIPAuthorization() bool { return !p.IPCaptureOnly }
func (p CapabilityProjection) ValidScope(scope string) bool {
	return scope != "" && scope != "destination-global" && scope != "recursive"
}
