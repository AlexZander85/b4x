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
func applyControlPlatform(p DialPolicy, _ string, _ string, c syscall.RawConn) error {
	if !p.Constrained() && !p.RequireMark {
		return nil
	}
	var ctrlErr error
	err := c.Control(func(fd uintptr) {
		raw := int(fd)
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
