//go:build linux

package transportwarp

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// applyControlPlatform pins the socket per policy. Every constraint is
// applied-or-fail: a partial application (mark without device) must not
// silently produce an unpinned socket (addendum §18).
func applyControlPlatform(p DialPolicy, network string, _ string, c syscall.RawConn) error {
	if !p.Constrained() && !p.RequireMark && !p.DisableUDPFragment {
		return nil
	}
	var ctrlErr error
	err := c.Control(func(fd uintptr) {
		raw := int(fd)
		// PATCH-31 (N-8): PLPMTUD-only UDP path — oversized datagrams fail
		// locally with EMSIZE instead of being IP-fragmented (design §7).
		if p.DisableUDPFragment {
			switch network {
			case "udp4":
				if e := unix.SetsockoptInt(raw, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); e != nil {
					ctrlErr = fmt.Errorf("transportwarp: IP_MTU_DISCOVER: %w", e)
					return
				}
			case "udp6":
				if e := unix.SetsockoptInt(raw, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO); e != nil {
					ctrlErr = fmt.Errorf("transportwarp: IPV6_MTU_DISCOVER: %w", e)
					return
				}
			}
		}
		if p.FwMark != 0 {
			ctrlErr = unix.SetsockoptInt(raw, unix.SOL_SOCKET, unix.SO_MARK, int(p.FwMark))
			if ctrlErr != nil {
				// M-04: a raw errno (EPERM, e.g. lacking CAP_NET_ADMIN) didn't match the
				// classifier's text branches; tag the SO_MARK layer so it yields FailureDialPolicy.
				ctrlErr = fmt.Errorf("transportwarp: SO_MARK: %w", ctrlErr)
				return
			}
		}
		if p.BindDevice != "" {
			iface, err := net.InterfaceByName(p.BindDevice)
			if err != nil {
				ctrlErr = fmt.Errorf("transportwarp: bind device %q: %w", p.BindDevice, err)
				return
			}
			ctrlErr = unix.BindToDevice(raw, iface.Name)
			if ctrlErr != nil {
				ctrlErr = fmt.Errorf("transportwarp: bind device %q: %w", iface.Name, ctrlErr)
				return
			}
		}
		if p.RequireMark && p.FwMark == 0 {
			ctrlErr = errors.New("transportwarp: policy requires SO_MARK but none configured")
		}
	})
	if err != nil {
		return err
	}
	return ctrlErr
}
