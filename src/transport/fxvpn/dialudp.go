// Constrained UDP carrier socket factory for the fxvpn H3 branch (addendum
// §18 as resolved in E-H3: marks ride the socket, not the QUIC layer —
// net.ListenConfig.Control applies SO_MARK/SO_BINDTODEVICE right after
// socket() and BEFORE bind, and the resulting *net.UDPConn is handed to
// quic.Dial). Fail-closed mirrors dialpolicy.go: a constrained policy on a
// platform that cannot apply it must never yield an unmarked socket.
package fxvpn

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// udpBufferBytes is the desired SO_RCVBUF/SO_SNDBUF (8 MB, best-effort —
// failures degrade throughput only).
const udpBufferBytes = 8 << 20

// ListenUDP creates one fxvpn UDP carrier socket for network
// ("udp", "udp4" or "udp6") under the policy constraints.
func (p DialPolicy) ListenUDP(ctx context.Context, network, laddr string) (*net.UDPConn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, &net.OpError{Op: "listen", Net: network, Err: syscall.EINVAL}
	}
	cfg := net.ListenConfig{
		Control: func(_ string, _ string, c syscall.RawConn) error {
			if err := p.applyControl("", "", c); err != nil {
				return err
			}
			_ = c.Control(func(fd uintptr) {
				raw := int(fd)
				_ = syscall.SetsockoptInt(raw, syscall.SOL_SOCKET, syscall.SO_RCVBUF, udpBufferBytes)
				_ = syscall.SetsockoptInt(raw, syscall.SOL_SOCKET, syscall.SO_SNDBUF, udpBufferBytes)
			})
			return nil
		},
	}
	pc, err := cfg.ListenPacket(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, &net.OpError{Op: "listen", Net: network, Err: errNotUDPPacketConn}
	}
	return uc, nil
}

var errNotUDPPacketConn = errors.New("fxvpn: listen packet did not return a UDP conn")
