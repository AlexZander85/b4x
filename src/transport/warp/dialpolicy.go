// DialPolicy controls how the engine's control socket reaches the endpoint
// (addendum v1.2 §17/§18: base control socket MUST carry an explicit
// B4-assigned SO_MARK and/or SO_BINDTODEVICE so it can never recurse into its
// own tunnel; "no silent fallback to unmarked socket").
//
// Zero-value Policy means "no routing constraint": used by unit tests and
// non-Linux builds. A Production instance MUST set Mark or BindToDevice; the
// supervisor enforces that at config validation time, and on platforms where
// a constrained policy cannot be applied the dial fails closed.
package transportwarp

import (
	"context"
	"net"
	"syscall"
	"time"
)

// dialTimeout bounds one TCP connect attempt of the control socket
// (warp-socks mod.rs uses 8s; usque L4 proxy 15s; we take 10s).
const dialTimeout = 10 * time.Second

// DialPolicy is applied via net.Dialer.ControlContext right after socket()
// and before connect. SourceIPv4 optionally pins the source address (nested
// inner instances bind the base TUN address).
type DialPolicy struct {
	// FwMark sets SO_MARK (Linux). Must come from the MarkAllocator-owned
	// space; the value is opaque here on purpose.
	FwMark uint32
	// BindDevice pins the socket to the named interface (SO_BINDTODEVICE),
	// e.g. the base TUN for inner control sockets.
	BindDevice string
	// SourceIPv4 pins the local source address when non-zero.
	SourceIPv4 [4]byte
	// RequireMark makes dial fail closed when mark application is not
	// possible (production posture; addendum forbids silent fallback).
	RequireMark bool
}

// applyControl implements the platform hook (dialpolicy_linux.go /
// dialpolicy_other.go): it runs inside RawConn.Control after socket creation.
func (p DialPolicy) applyControl(network, address string, c syscall.RawConn) error {
	return applyControlPlatform(p, network, address, c)
}

// Dialer returns a net.Dialer carrying this policy.
func (p DialPolicy) Dialer() *net.Dialer {
	d := &net.Dialer{
		Timeout: dialTimeout,
		ControlContext: func(_ context.Context, network, address string, c syscall.RawConn) error {
			return p.applyControl(network, address, c)
		},
	}
	if p.SourceIPv4 != ([4]byte{}) {
		d.LocalAddr = &net.TCPAddr{IP: net.IP(p.SourceIPv4[:])}
	}
	return d
}

// Constrained reports whether the policy actually pins the path.
func (p DialPolicy) Constrained() bool {
	return p.FwMark != 0 || p.BindDevice != "" || p.SourceIPv4 != ([4]byte{})
}
