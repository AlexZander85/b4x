//go:build !linux

// Non-Linux stub: the bait needs iptables/nftables + SO_MARK; honest
// no-op (NFWBait.Active stays false — the status never lies).
package operaservice

import "syscall"

// baitControl returns nil — no socket marking on this platform.
func baitControl() func(network, address string, c syscall.RawConn) error {
	return nil
}
