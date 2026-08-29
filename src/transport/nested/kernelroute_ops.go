// KernelRouteCarrier part 2: the supervisor-tick assertion loop (the fix
// for the documented zapret-gui restart gap), teardown ownership, and the
// NestedCarrier surface.
package nested

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Assert re-verifies every owned pin NOW and repairs lost ones. This is the
// tick body of the supervisor loop: an outer recreate that wiped the pin is
// repaired automatically instead of requiring a manual re-setup.
func (c *KernelRouteCarrier) Assert(ctx context.Context) error {
	if c.closed.Load() {
		return ErrCarrierClosed
	}
	owned := c.ownedList()

	repaired := false
	var lastErr error
	for _, r := range owned {
		if err := c.verifyRoute(ctx, r.family, r.dst); err != nil {
			lastErr = err
			// B-N2 (PATCH-06): one route-lost event per episode — re-emit
			// only after a successful repair closed the previous episode.
			if !r.lostActive {
				c.emit(Event{Class: ClassCarrierRouteLost, Reason: err.Error()})
				c.setLostActive(r.dst, true)
			}
			if perr := c.repairPin(ctx, r); perr != nil {
				c.proofOK.Store(false)
				return perr
			}
			// Episode closed: the repair landed; the ClassPinRestored emit
			// below is the single episode-close signal.
			c.setLostActive(r.dst, false)
			repaired = true
		}
	}
	if len(owned) > 0 && c.coverageOK() {
		c.proofOK.Store(true)
	}
	if repaired && c.proofOK.Load() {
		c.emit(Event{Class: ClassPinRestored, Reason: "re-assert repinned all owned routes"})
	}
	if lastErr != nil && !c.proofOK.Load() {
		return lastErr
	}
	return nil
}

// repairPin re-applies one pin keeping its original previous-route evidence.
func (c *KernelRouteCarrier) repairPin(ctx context.Context, r pinnedRoute) error {
	if _, err := c.cfg.Runner(ctx, r.family, "route", "replace",
		r.dst.String()+"/"+prefixLenOf(r.family), "dev", c.cfg.Device); err != nil {
		return fmt.Errorf("repin %s: %v", r.dst, err)
	}
	return c.verifyRoute(ctx, r.family, r.dst)
}

// RunAssertionLoop asserts every interval until ctx cancellation or Close.
// It never returns errors: failures surface as structured events.
func (c *KernelRouteCarrier) RunAssertionLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	c.loopWg.Add(1)
	go func() {
		defer c.loopWg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-t.C:
				actx, cancel := context.WithTimeout(ctx, 5*time.Second)
				_ = c.Assert(actx)
				cancel()
			}
		}
	}()
}

// StopAssertionLoop stops the background ticker (idempotent).
func (c *KernelRouteCarrier) StopAssertionLoop() { closeOnce(c.stopCh) }

// Restore tears down ALL owned pins, restoring each previous route VERBATIM
// (token-split replace) when one existed and was NOT ours; else deleting
// exactly our pin. Foreign routes are never removed (cleanup ownership).
func (c *KernelRouteCarrier) Restore(ctx context.Context) {
	c.mu.Lock()
	owned := c.owned
	c.owned = nil
	c.mu.Unlock()
	c.proofOK.Store(false)

	for _, r := range owned {
		prev := strings.Fields(strings.TrimSpace(r.prev))
		if len(prev) > 0 && !strings.Contains(r.prev, "dev "+c.cfg.Device) {
			full := append([]string{r.family, "route", "replace"}, stripFamilyTokens(prev, r.family)...)
			if _, err := c.cfg.Runner(ctx, full...); err == nil {
				continue
			}
		}
		_, _ = c.cfg.Runner(ctx, r.family, "route", "del",
			r.dst.String()+"/"+prefixLenOf(r.family), "dev", c.cfg.Device)
	}
}

// DialUDPThrough opens one CONNECTED UDP socket toward dst; the kernel
// routes both directions through the owned pin. The returned net.Conn
// satisfies the transportwg forwarder's udpConn surface structurally.
// Fail-closed: no verified pin, no dial.
func (c *KernelRouteCarrier) DialUDPThrough(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if c.closed.Load() {
		return nil, ErrCarrierClosed
	}
	if !c.proofOK.Load() {
		return nil, fmt.Errorf("%w: udp dial to %v refused", ErrCarrierUnproven, dst)
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, "udp", dst.String())
}

// InjectUDPDatagram sends one datagram toward dst through a short-lived
// socket; the kernel routes it via the owned pin. Relay consumers should
// prefer DialUDPThrough (one connected session, replies find their way back).
func (c *KernelRouteCarrier) InjectUDPDatagram(dst netip.AddrPort, payload []byte) error {
	conn, err := c.DialUDPThrough(context.Background(), dst)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, werr := conn.Write(payload)
	return werr
}

// DialTCPThrough opens one TCP stream; the kernel routes via the pin.
// Fail-closed: no verified pin, no dial (red line #1).
func (c *KernelRouteCarrier) DialTCPThrough(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if c.closed.Load() {
		return nil, ErrCarrierClosed
	}
	if !c.proofOK.Load() {
		return nil, fmt.Errorf("%w: tcp dial to %v refused", ErrCarrierUnproven, dst)
	}
	return c.dialerD(ctx, "tcp", dst.String())
}

// ProofSnapshot reports the verified pin set as carrier evidence.
func (c *KernelRouteCarrier) ProofSnapshot() (string, bool) {
	list := c.ownedList()
	if !c.proofOK.Load() || len(list) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(list))
	for _, r := range list {
		parts = append(parts, r.dst.String()+"@"+r.dev)
	}
	return "pins:" + strings.Join(parts, ","), true
}

// Close stops the assertion loop and marks the carrier closed. Routes are
// NOT restored implicitly: teardown order belongs to the pair runtime
// (child-first, then carrier Restore).
func (c *KernelRouteCarrier) Close() {
	c.closed.Store(true)
	closeOnce(c.stopCh)
}

// ---- family helpers ----

func familyOf(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "-4"
	}
	return "-6"
}

func isMandatoryFamily(a netip.Addr, p FamilyPolicy) bool {
	f := familyOf(a)
	if f == "-4" {
		return p.RequireV4
	}
	return false // v6 is warn-only by policy construction
}

func prefixLenOf(family string) string {
	if family == "-4" {
		return "32"
	}
	return "128"
}

// stripFamilyTokens drops iproute2 tokens that are invalid after the
// explicit family selector when re-issuing a stored line verbatim.
func stripFamilyTokens(tok []string, family string) []string {
	out := make([]string, 0, len(tok))
	for _, t := range tok {
		if t == "-4" || t == "-6" || t == family {
			continue
		}
		out = append(out, t)
	}
	return out
}
