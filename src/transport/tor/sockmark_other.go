//go:build !linux

// Non-Linux stub: tor egress marking needs SO_MARK + OUTPUT mangle; the
// dialer runs unmarked (dev/test builds only — the router is linux).
package tor

import "syscall"

// egressMarkControl returns nil — no socket marking on this platform.
func egressMarkControl() func(network, address string, c syscall.RawConn) error {
	return nil
}
