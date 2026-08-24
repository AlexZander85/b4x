//go:build linux

// Linux socket pinning for the WG bind: SO_MARK + SO_BINDTODEVICE,
// apply-or-fail (a partial application must never yield an unpinned socket;
// same posture as src/transport/warp/dialpolicy_linux.go).
package transportwg

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// applySocketControl runs inside net.ListenConfig.Control right after
// socket(2) and before bind(2).
func applySocketControl(c syscall.RawConn, opts SocketOptions, mark uint32) error {
	if !opts.Constrained() && mark == 0 && !opts.RequireMark {
		return nil
	}
	var ctrlErr error
	err := c.Control(func(fd uintptr) {
		raw := int(fd)
		effective := opts.FwMark
		if effective == 0 {
			effective = mark
		}
		if opts.RequireMark && effective == 0 {
			ctrlErr = errors.New("transportwg: policy requires SO_MARK but none configured")
			return
		}
		if effective != 0 {
			if err := unix.SetsockoptInt(raw, unix.SOL_SOCKET, unix.SO_MARK, int(effective)); err != nil {
				ctrlErr = fmt.Errorf("transportwg: SO_MARK(%d): %w", effective, err)
				return
			}
		}
		if opts.BindDevice != "" {
			iface, err := net.InterfaceByName(opts.BindDevice)
			if err != nil {
				ctrlErr = fmt.Errorf("transportwg: bind device %q: %w", opts.BindDevice, err)
				return
			}
			if err := unix.BindToDevice(raw, iface.Name); err != nil {
				ctrlErr = fmt.Errorf("transportwg: SO_BINDTODEVICE(%q): %w", iface.Name, err)
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return ctrlErr
}

// setMarkOnConn applies a mark update to an already-open UDP socket.
func setMarkOnConn(c *net.UDPConn, mark uint32) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return fmt.Errorf("transportwg: syscall conn: %w", err)
	}
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		ctrlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	}); err != nil {
		return err
	}
	if ctrlErr != nil {
		return fmt.Errorf("transportwg: SO_MARK(%d): %w", mark, ctrlErr)
	}
	return nil
}

// isFamilyUnsupported reports whether err means "this address family does not
// exist on this kernel" (tolerated in Open, mirroring upstream EAFNOSUPPORT).
func isFamilyUnsupported(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, unix.EAFNOSUPPORT)
}
