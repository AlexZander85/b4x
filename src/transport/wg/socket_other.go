//go:build !linux

// Non-Linux platforms: scoped socket options are not applied. The zero-value
// policy stays usable (unit tests); a constrained policy fails closed —
// production posture forbids silently unpinned tunnel sockets.
package transportwg

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
)

func applySocketControl(_ syscall.RawConn, opts SocketOptions, mark uint32) error {
	if !opts.Constrained() && mark == 0 && !opts.RequireMark {
		return nil
	}
	return fmt.Errorf("transportwg: scoped socket policy (SO_MARK/SO_BINDTODEVICE) is not supported on %s; refusing unconstrained socket", runtime.GOOS())
}

func setMarkOnConn(_ *net.UDPConn, mark uint32) error {
	if mark == 0 {
		return nil
	}
	return errors.New("transportwg: SO_MARK is not supported on this platform")
}

func isFamilyUnsupported(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT)
}
