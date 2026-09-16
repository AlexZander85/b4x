// Daemon-assembly accessors (tunnels panel stage 2): the composed runtimes
// own their INNER layers privately by design; the service wiring
// (src/warpchainservice) is the legitimate consumer that needs a SNAPSHOT
// of the live inner surface to expose the reserve.Carrier data plane. The
// accessors never hand out lifecycle control — snapshots only, nil when the
// layer is down, exactly like Session.Tunnel().
package nested

import (
	twarp "github.com/daniellavrushin/b4/transport/warp"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// InnerSession snapshots the live INNER AWG session of an M+W composition
// (masque outer carrying an awg inner). nil while the child is down; a
// returned session is ESTABLISHED (startChild only stores established
// sessions, stopChild clears the field first). The consumer reads
// Tunnel().Netstack for the data plane — the same carrier contract as every
// single-transport wg service.
func (r *MasqueAwgRuntime) InnerSession() *twg.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner
}

// InnerSupervisor snapshots the live INNER MASQUE supervisor of a W+M
// composition (awg outer carrying a masque inner). nil while the child is
// down. The consumer attaches the supervisor's netstack
// (AttachNetstack + AssignedLocalV4) for the data plane.
func (r *WgMasqueRuntime) InnerSupervisor() *twarp.Supervisor {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner
}
