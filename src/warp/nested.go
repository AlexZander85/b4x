package warp

type TunnelDependencyLink struct {
	ParentSession, InnerSession, ParentGeneration string
	Valid                                         bool
}
type NestedBackend struct {
	Namespace, Veth, NAT string
	Link                 TunnelDependencyLink
	Active               bool
	CleanupOwned         bool
}

func (n NestedBackend) Valid() bool {
	return n.Namespace != "" && n.Veth != "" && n.NAT != "" && n.Link.Valid && n.CleanupOwned
}
func (n *NestedBackend) InvalidateParent() {
	if n != nil {
		n.Active = false
		n.Link.Valid = false
	}
}
func (n *NestedBackend) Cleanup() {
	if n != nil {
		n.Active = false
		n.CleanupOwned = true
		n.Namespace = ""
		n.Veth = ""
		n.NAT = ""
	}
}
