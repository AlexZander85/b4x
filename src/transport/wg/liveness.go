// Nested liveness probe (FIELD3, bd b4x-ari/b4x-mrl). Diagnostic for the
// nested data path: the probe dials TLS through the INNER netstack and reports
// the OUTER device's rx_bytes delta (the reply traverses the outer on the way
// back). Used to confirm whether a given outer profile actually carries data.
package transportwg

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"
)

const nestedProbeInterval = 10 * time.Second

const (
	nestedProbeAddr = "1.1.1.1:443"
	nestedProbeSNI  = "one.one.one.one"
)

func (r *NestedWgRuntime) startInnerProbe(ctx context.Context, sess *Session, gen uint64) context.CancelFunc {
	if sess == nil {
		return func() {}
	}
	pctx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(nestedProbeInterval)
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

func (r *NestedWgRuntime) probeInnerOnce(ctx context.Context, sess *Session, gen uint64) {
	tun := sess.Tunnel()
	if tun == nil || tun.Netstack == nil {
		r.emit(SessionEvent{Name: "wg_nested_probe", Reason: fmt.Sprintf("gen=%d no-inner-netstack", gen)})
		return
	}
	before := r.outer.Telemetry()
	dial := nsTCPDial(tun.Netstack)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dial(cctx, "tcp", nestedProbeAddr)
	if err != nil {
		delta := int64(r.outer.Telemetry().RXBytes) - int64(before.RXBytes)
		r.emit(SessionEvent{Name: "wg_nested_probe", Reason: fmt.Sprintf("gen=%d inner_dial_fail=%v outer_rx_delta=%d", gen, err, delta)})
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	tc := tls.Client(conn, &tls.Config{ServerName: nestedProbeSNI, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
	herr := tc.HandshakeContext(cctx)
	_ = tc.Close()
	delta := int64(r.outer.Telemetry().RXBytes) - int64(before.RXBytes)
	r.emit(SessionEvent{Name: "wg_nested_probe", Reason: fmt.Sprintf("gen=%d hs_ok=%t outer_rx_delta=%d", gen, herr == nil, delta)})
}
