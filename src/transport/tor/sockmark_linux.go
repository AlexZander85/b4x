//go:build linux

// Socket marking for the Tor egress dialer (design §3.2/§3.4): the DIRECT
// legs get SO_MARK = packetmark.MarkTorEgress via net.Dialer.Control (the
// operaservice baitControl pattern). The OUTPUT mangle layer then routes
// the marked packets into the action queue (bait_profile=first-flight:
// the fake first flight protects the tunnel's own handshakes) or into the
// engine bypass (bait=none: never loop back into the classifier).
package tor

import (
	"syscall"

	"github.com/daniellavrushin/b4/packetmark"
)

// egressMarkControl tags every outbound socket with the tor egress mark.
func egressMarkControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var ctrlErr error
		if err := c.Control(func(fd uintptr) {
			ctrlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(packetmark.MarkTorEgress))
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}
