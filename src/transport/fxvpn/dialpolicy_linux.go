//go:build linux

package fxvpn

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// applyControlPlatform pins the socket per policy. Every constraint is
// applied-or-fail: a partial application must not silently produce an
// unpinned socket (addendum §18).
func applyControlPlatform(p DialPolicy, c syscall.RawConn) error {
	if !p.Constrained() && !p.RequireMark {
		return nil
	}
	var ctrlErr error
	err := c.Control(func(fd uintptr) {
		raw := int(fd)
		if p.FwMark != 0 {
			ctrlErr = unix.SetsockoptInt(raw, unix.SOL_SOCKET, unix.SO_MARK, int(p.FwMark))
			if ctrlErr != nil {
				return
			}
		}
		if p.BindDevice != "" {
			iface, err := net.InterfaceByName(p.BindDevice)
			if err != nil {
				ctrlErr = fmt.Errorf("fxvpn: bind device %q: %w", p.BindDevice, err)
				return
			}
			ctrlErr = unix.BindToDevice(raw, iface.Name)
			if ctrlErr != nil {
				return
			}
		}
		if p.RequireMark && p.FwMark == 0 {
			ctrlErr = errors.New("fxvpn: policy requires SO_MARK but none configured")
		}
	})
	if err != nil {
		return err
	}
	return ctrlErr
}
