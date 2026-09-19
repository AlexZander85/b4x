// Nested liveness probe (FIELD3, bd b4x-ari/b4x-mrl/b4x-sce). The passive
// tx-gated rx-idle watchdog false-fires on a quiet-but-live nested outer
// because CF edges do not answer idle keepalives and the outer's own data path
// produces no >256 B RX while idle. The probe sends a real TLS request through
// the tunnel; the reply (>MinRXGrowth bytes) moves the owning session's rx
// anchor, so a live-but-quiet path stays up while a dead one still stalls.
//
//   - StartLivenessProbe(ctx, ns, interval): generic, no sink (transport/nested
//     uses it on the W+M OUTER netstack - b4x-sce).
//   - startInnerProbe/probeInnerOnce: instrumented variant on the W+W INNER
//     netstack that also emits wg_nested_probe with the outer rx delta.
package transportwg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// NestedProbeInterval paces the liveness probe; must stay below the derived
// rx-idle (max(30s, 3*keepalive)).
const NestedProbeInterval = 10 * time.Second

const (
	nestedProbeAddr = "1.1.1.1:443"
	nestedProbeSNI  = "one.one.one.one"
)

// StartLivenessProbe runs the periodic TLS probe through ns until ctx is done.
// Safe with a nil netstack (no-op). Exported for the nested matrix runtimes.
func StartLivenessProbe(ctx context.Context, ns *netstack.Net, interval time.Duration) context.CancelFunc {
	if ns == nil || interval <= 0 {
		return func() {}
	}
	pctx, cancel := context.WithCancel(ctx)
	dial := nsTCPDial(ns)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-pctx.Done():
				return
			case <-t.C:
				probeTLSOnce(pctx, dial)
			}
		}
	}()
	return cancel
}

// probeTLSOnce issues one TLS probe; failures are silent (the passive watchdog
// remains the loss authority - the probe only feeds its rx anchor).
func probeTLSOnce(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) bool {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dial(cctx, "tcp", nestedProbeAddr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	tc := tls.Client(conn, &tls.Config{ServerName: nestedProbeSNI, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
	herr := tc.HandshakeContext(cctx)
	_ = tc.Close()
	return herr == nil
}

// startInnerProbe runs the instrumented probe through the INNER session's
// netstack until ctx is done. sess is the live inner generation.
func (r *NestedWgRuntime) startInnerProbe(ctx context.Context, sess *Session, gen uint64) context.CancelFunc {
	if sess == nil {
		return func() {}
	}
	pctx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(NestedProbeInterval)
		defer t.Stop()
		for {
			select {
			case <-pctx.Done():
				return
			case <-t.C:
				r.probeInnerOnce(pctx, sess, gen)
			}
		}
	}()
	return cancel
}

// probeInnerOnce dials TLS through the inner netstack and reports the OUTER
// device's rx_bytes delta (the reply traverses the outer on the way back).
func (r *NestedWgRuntime) probeInnerOnce(ctx context.Context, sess *Session, gen uint64) {
	tun := sess.Tunnel()
	if tun == nil || tun.Netstack == nil {
		r.emit(SessionEvent{Name: "wg_nested_probe", Reason: fmt.Sprintf("gen=%d no-inner-netstack", gen)})
		return
	}
	before := r.outer.Telemetry()
	ok := probeTLSOnce(ctx, nsTCPDial(tun.Netstack))
	delta := int64(r.outer.Telemetry().RXBytes) - int64(before.RXBytes)
	r.emit(SessionEvent{Name: "wg_nested_probe", Reason: fmt.Sprintf("gen=%d hs_ok=%t outer_rx_delta=%d", gen, ok, delta)})
}
