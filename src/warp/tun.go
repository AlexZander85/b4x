package warp

import "errors"

type TunState string

const (
	TunAbsent   TunState = "absent"
	TunOwned    TunState = "owned"
	TunVerified TunState = "verified"
	TunStale    TunState = "stale"
)

type TunLease struct {
	SessionID, Interface, Address string
	MTU                           int
	State                         TunState
}

func (l TunLease) Valid() bool {
	return l.SessionID != "" && l.Interface != "" && l.Address != "" && l.MTU >= 1280 && (l.State == TunOwned || l.State == TunVerified)
}

type TunRegistry struct{ leases map[string]TunLease }

func NewTunRegistry() *TunRegistry { return &TunRegistry{leases: map[string]TunLease{}} }
func (r *TunRegistry) Claim(l TunLease) error {
	if r == nil || !l.Valid() {
		return errors.New("invalid tun lease")
	}
	if old, ok := r.leases[l.Interface]; ok && old.SessionID != l.SessionID {
		return errors.New("tun interface collision")
	}
	r.leases[l.Interface] = l
	return nil
}
func (r *TunRegistry) Release(iface, session string) bool {
	if r == nil {
		return false
	}
	l, ok := r.leases[iface]
	if !ok || l.SessionID != session {
		return false
	}
	delete(r.leases, iface)
	return true
}
func (r *TunRegistry) Reconcile(iface string) TunState {
	if r == nil {
		return TunAbsent
	}
	l, ok := r.leases[iface]
	if !ok {
		return TunAbsent
	}
	return l.State
}
