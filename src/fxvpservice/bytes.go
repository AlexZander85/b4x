// bytes.go: data-plane byte accounting (review F7b): tunnelConn relays are
// wrapped in DialStream with atomics counters + the shared observability
// registry gauge fxvpn_bytes_total{dir=up|down}, and the Status view gains
// the totals. The local byte counter pairs with the 15-min X-Quota-* poll
// (design Ч.I §3) — the GUI progress bar stops showing hours-old numbers.
package fxvpservice

import (
	"net"
	"sync/atomic"

	"github.com/daniellavrushin/b4/observability"
)

// byteCountingConn wraps one relay and feeds the runtime counters.
type byteCountingConn struct {
	net.Conn
	rt *Runtime
}

func (c byteCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rt.recordBytes(false, n)
	}
	return n, err
}

func (c byteCountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.rt.recordBytes(true, n)
	}
	return n, err
}

// recordBytes bumps the runtime atomics AND the shared registry counter.
func (r *Runtime) recordBytes(up bool, n int) {
	if n <= 0 {
		return
	}
	dir := "down"
	if up {
		dir = "up"
		atomic.AddUint64(&r.bytesUp, uint64(n))
	} else {
		atomic.AddUint64(&r.bytesDown, uint64(n))
	}
	observability.Default().Metrics.Inc(observability.MetricFxvpnBytesTotal, map[string]string{"dir": dir}, uint64(n))
}
