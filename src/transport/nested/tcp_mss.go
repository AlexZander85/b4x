// Explicit MSS clamp for carrier-dialed TCP (design 3.3): PMTU discovery
// across two tunnel layers is unreliable, so the W+M wiring sets the inner
// control segment size EXPLICITLY on the kernel-route path. The netstack
// carrier needs no knob - gVisor segments against its own MTU.
//
// Linux-only effect: TCP_MAXSEG via setsockopt at socket creation. Other
// platforms return the base dialer unchanged (documented limitation; the
// kernel-route carrier itself is linux-only anyway).
package nested

import (
	"context"
	"net"
	"syscall"
	"time"
)

// DialerWithMSS returns a dialer whose sockets get TCP_MAXSEG=mss. A nil
// base produces a sane default dialer (bounded timeout). mss<=0 returns the
// base unchanged. Any pre-existing ControlContext is preserved and runs
// AFTER the MSS option (apply-or-fail semantics of the base stay intact).
func DialerWithMSS(base *net.Dialer, mss int) *net.Dialer {
	if mss <= 0 {
		if base == nil {
			return &net.Dialer{Timeout: 5 * time.Second}
		}
		return base
	}
	if base == nil {
		base = &net.Dialer{Timeout: 5 * time.Second}
	}
	prev := base.ControlContext
	d := *base
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		var ctlErr error
		if err := c.Control(func(fd uintptr) {
			ctlErr = setTCPMaxSeg(fd, mss)
		}); err != nil {
			return err
		}
		if ctlErr != nil {
			return ctlErr
		}
		if prev != nil {
			return prev(ctx, network, address, c)
		}
		return nil
	}
	return &d
}
