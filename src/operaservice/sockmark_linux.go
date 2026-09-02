//go:build linux

// Socket marking for the Opera bait (review E-OPERA §7.4.3, OP-M3): the
// transport's DIRECT egress dialer gets SO_MARK =
// packetmark.MarkOperaEgress via net.Dialer.Control (pattern:
// transport/wg/socket_linux.go), so the OUTPUT mangle rule routes exactly
// these packets into the action queue for the fakedsplit/fakeddisorder
// first-flight treatment. The CARRIER stage is deliberately unmarked
// (§7.8.3: the bait never applies to traffic that already rides another
// tunnel — double obfuscation is a marker of its own).
package operaservice

import (
	"fmt"
	"syscall"

	"github.com/daniellavrushin/b4/packetmark"
)

// baitControl returns a net.Dialer.Control tagging every outbound socket
// with the opera egress mark; nil (other platforms) disables the bait.
func baitControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var ctrlErr error
		if err := c.Control(func(fd uintptr) {
			ctrlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(packetmark.MarkOperaEgress))
		}); err != nil {
			return err
		}
		if ctrlErr != nil {
			return fmt.Errorf("operaservice: SO_MARK(%d): %w", packetmark.MarkOperaEgress, ctrlErr)
		}
		return nil
	}
}
