package warp

type TunnelDependencyLink struct {
	ParentSession, InnerSession, ParentGeneration string
	// ParentRouteID/ParentRouteGen are the parent route token and its
	// generation the child is currently bound to (addendum §62.4).
	ParentRouteID  string
	ParentRouteGen uint64
	// ParentSessionGen is the parent session generation the link was
	// revalidated against; ParentHealthy reflects the live parent health
	// state required for child promotion.
	ParentSessionGen uint64
	ParentHealthy    bool
	// Revalidated is true when the link has been revalidated against the
	// current parent session generation after a parent reconnect.
	Revalidated bool
	Valid       bool
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
		n.Link.Revalidated = false
	}
}
func (n *NestedBackend) RevalidateParent(sessionGen uint64, healthy bool) {
	if n != nil {
		n.Link.ParentSessionGen = sessionGen
		n.Link.ParentHealthy = healthy
		n.Link.Revalidated = true
	}
}
func (n *NestedBackend) UseParentToken(parentRouteID string) (string, bool) {
	if n == nil || !n.Link.Valid || n.Link.ParentRouteID != parentRouteID {
		return "", false
	}
	return parentRouteID, true
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
