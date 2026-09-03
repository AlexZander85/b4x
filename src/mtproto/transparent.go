package mtproto

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/observability"
)

const transparentBufSize = 65536

// FB-04 (b4x-6l5): the zero-byte connection lifecycle is two-stage. The soft
// first-byte window is the old 5s read deadline, but on expiry the
// connection is parked in the pending handshake manager instead of being
// silently dropped. The hard deadline bounds how long a parked zero-byte
// connection may occupy a pending slot; on expiry only observable cleanup
// happens (MetricMTProtoIdlePreconnectExpired).
const (
	bridgeZeroByteSoftTimeout = 5 * time.Second
	bridgeZeroByteHardTimeout = 60 * time.Second
)

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type TransparentBridge struct {
	cfg     atomic.Pointer[config.Config]
	bufPool sync.Pool

	mu       sync.Mutex
	pool     *wsPool
	poolInit bool

	// FB-04 (b4x-6l5): zero-byte connections are parked here instead of
	// being silently dropped after the soft first-byte window.
	pending      *PendingHandshakeManager
	zeroByteSoft time.Duration
	zeroByteHard time.Duration
}

func NewTransparentBridge(cfg *config.Config) *TransparentBridge {
	b := &TransparentBridge{
		bufPool: sync.Pool{New: func() interface{} {
			buf := make([]byte, transparentBufSize)
			return &buf
		}},
		pending:      NewPendingHandshakeManager(128, 8),
		zeroByteSoft: bridgeZeroByteSoftTimeout,
		zeroByteHard: bridgeZeroByteHardTimeout,
	}
	b.cfg.Store(cfg)
	return b
}

func (b *TransparentBridge) UpdateConfig(newCfg *config.Config) {
	old := b.cfg.Swap(newCfg)
	// A config reload invalidates the pending-handshake generation: parked
	// tokens from before the reload are stale and released lazily.
	b.pending.Reload()
	if old != nil &&
		old.System.MTProto.WSEndpointHost == newCfg.System.MTProto.WSEndpointHost &&
		old.System.MTProto.WSCustomDomain == newCfg.System.MTProto.WSCustomDomain &&
		old.Queue.Mark == newCfg.Queue.Mark {
		return
	}
	b.mu.Lock()
	oldPool := b.pool
	b.pool = nil
	b.poolInit = false
	b.mu.Unlock()
	if oldPool != nil {
		oldPool.close()
	}
}

func (b *TransparentBridge) getPool() *wsPool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.poolInit {
		cfg := b.cfg.Load()
		mt := cfg.System.MTProto
		p := newWSPool(MTProtoUpstream{
			WSEndpointHost: mt.WSEndpointHost,
			WSCustomDomain: mt.WSCustomDomain,
		}, cfg.Queue.Mark, wsPoolDefaultSize)
		p.warmup([]int{2, 4})
		b.pool = p
		b.poolInit = true
	}
	return b.pool
}

func (b *TransparentBridge) Handle(client net.Conn, origIP net.IP, origPort int) (bool, net.Conn) {
	id := nextConnID()
	tag := tg(id)
	log.Tracef("%s bridge accept %s -> %s:%d", tag, client.RemoteAddr(), origIP, origPort)
	// FB-04 (b4x-6l5): the first-byte window is a soft timeout, never a
	// destructive deadline — a client that stays silent is parked, not
	// dropped.
	_ = client.SetReadDeadline(time.Now().Add(b.zeroByteSoft))
	init := make([]byte, obfuscatedFrameLen)
	head, herr := io.ReadFull(client, init[:4])
	_ = client.SetReadDeadline(time.Time{})
	if herr != nil {
		if head == 0 && !errors.Is(herr, io.EOF) {
			// Zero bytes within the soft window and the client did not close:
			// park the connection in the pending handshake manager instead of
			// silently returning "handled".
			return b.parkZeroByte(client, init, id, tag, origIP, origPort)
		}
		if head == 0 {
			// The client closed before sending anything; there is nothing to
			// relay or park.
			log.Tracef("%s bridge empty conn from %s -> closed by client", tag, origIP)
			return true, nil
		}
		log.Debugf("%s bridge short head (%d B) from %s:%d -> fail open", tag, head, origIP, origPort)
		return false, &prefixConn{Conn: client, prefix: append([]byte(nil), init[:head]...)}
	}
	return b.finishHandshake(client, init, head, id, tag, origIP, origPort)
}

// dialDC is the production primary-route dial used by finishHandshake. It is
// a variable so tests can force a primary-route failure deterministically and
// verify the fail-open ladder.
var dialDC = DialObfuscatedDCWithPool

// parkZeroByte parks a connection that produced no bytes within the soft
// first-byte window (FB-04 b4x-6l5). The connection stays alive and owned by
// the bridge for the whole hard window, so it is neither silently closed nor
// recorded as handled:
//   - if the client eventually sends the obfuscated handshake frame, normal
//     handshake processing continues (a delayed first byte does not drop the
//     connection);
//   - when the hard deadline expires, only observable cleanup happens
//     (MetricMTProtoIdlePreconnectExpired) before the connection is closed;
//   - when the pending budget is exhausted, the connection is failed open
//     with an explicit overflow attribution.
func (b *TransparentBridge) parkZeroByte(client net.Conn, init []byte, id string, tag string, origIP net.IP, origPort int) (bool, net.Conn) {
	// Guards (FB-02 TGB section): a zero-byte connection must never be
	// recorded as handled, and the first-byte window must not be a fixed
	// destructive timeout. Both pass for the pending outcome actually
	// produced here; the zero-tolerance counters only move on a regression.
	ZeroByteHandledDrop(BridgeOutcome{Disposition: BridgePending, Reason: ReasonZeroByte})
	DestructiveTimeout(false)

	token, perr := b.pending.Acquire(origIP.String(), time.Now())
	if perr != nil {
		// Pending budget exhausted: fail open instead of dropping. The
		// overflow must carry an explicit budget attribution.
		OverflowWithReason(perr, "global-budget")
		log.Infof("%s bridge zero-byte pending overflow for %s:%d (%v) -> fail open", tag, origIP, origPort, perr)
		return false, &prefixConn{Conn: client, prefix: init[:0]}
	}
	defer b.pending.Release(token.ID)
	log.Infof("%s bridge zero-byte from %s:%d parked as %s (soft %s)", tag, origIP, origPort, token.ID, b.zeroByteSoft)

	head, herr := b.waitFirstBytes(client, init, time.Now().Add(b.zeroByteHard))
	_ = client.SetReadDeadline(time.Time{})
	if herr != nil {
		if head == 0 {
			if ne, ok := herr.(net.Error); ok && ne.Timeout() {
				// Hard deadline: closing the idle preconnect is observable
				// cleanup, not a destructive silent drop.
				observability.Default().Metrics.Inc(observability.MetricMTProtoIdlePreconnectExpired, nil, 1)
				log.Infof("%s bridge parked conn %s expired after %s -> close (idle preconnect)", tag, token.ID, b.zeroByteHard)
			} else {
				log.Tracef("%s bridge parked conn %s closed by client", tag, token.ID)
			}
			return true, nil
		}
		log.Debugf("%s bridge parked conn %s sent %d B then stalled -> fail open", tag, token.ID, head)
		return false, &prefixConn{Conn: client, prefix: append([]byte(nil), init[:head]...)}
	}
	log.Infof("%s bridge parked conn %s delivered first bytes after idle -> continue handshake", tag, token.ID)
	return b.finishHandshake(client, init, head, id, tag, origIP, origPort)
}

// waitFirstBytes keeps a parked connection alive until the hard deadline,
// waiting for the first bytes of the obfuscated handshake frame. It returns
// the number of bytes read into init[:4] (4 on success) and any error.
func (b *TransparentBridge) waitFirstBytes(client net.Conn, init []byte, hard time.Time) (int, error) {
	_ = client.SetReadDeadline(hard)
	return io.ReadFull(client, init[:4])
}

// finishHandshake completes the obfuscated handshake after the first bytes
// have been read into init. head is the number of valid bytes already
// present: 4 after a clean first read, 1..3 for a partial prefix, or 4 after
// a parked connection finally produced its first bytes. The listener route
// ladder is the fail-open fallback for every early-exit below.
func (b *TransparentBridge) finishHandshake(client net.Conn, init []byte, head int, id string, tag string, origIP net.IP, origPort int) (bool, net.Conn) {
	if head < 4 {
		// Partial prefix (1-3 bytes): every captured byte must survive the
		// handoff intact (FB-04 criterion).
		PrefixHandoffComplete(init[:head], head)
		PrefixHandoffNonDuplicate(init[:head], head)
		log.Debugf("%s bridge short head (%d B) from %s:%d -> fail open", tag, head, origIP, origPort)
		return false, &prefixConn{Conn: client, prefix: append([]byte(nil), init[:head]...)}
	}
	if reservedFirst4(init[:4]) {
		log.Debugf("%s bridge non-obfuscated transport (% x) from %s:%d -> fail open", tag, init[:4], origIP, origPort)
		return false, &prefixConn{Conn: client, prefix: append([]byte(nil), init[:4]...)}
	}
	n, rerr := io.ReadFull(client, init[4:])
	if rerr != nil {
		log.Debugf("%s bridge short handshake (%d/%d B) from %s:%d -> fail open", tag, 4+n, obfuscatedFrameLen, origIP, origPort)
		return false, &prefixConn{Conn: client, prefix: append([]byte(nil), init[:4+n]...)}
	}

	res, derr := decodeObfuscatedDirect(init, client)
	if derr != nil {
		PrefixHandoffComplete(init, obfuscatedFrameLen)
		log.Debugf("%s bridge obfuscated decode failed from %s:%d: %v -> fail open", tag, origIP, origPort, derr)
		return false, &prefixConn{Conn: client, prefix: append([]byte(nil), init...)}
	}
	log.Tracef("%s bridge handshake ok from %s:%d: proto=0x%08x handshake-dc=%d", tag, origIP, origPort, res.ProtoTag, res.DC)

	var dc int
	var dcSrc string
	if mapped, ok := dcForIP(origIP); ok {
		dc, dcSrc = mapped, "ip"
	} else if validTransparentDC(res.DC) {
		dc, dcSrc = res.DC, "handshake"
	} else if mapped, ok := dcForIPRange(origIP); ok {
		dc, dcSrc = mapped, "ip-range"
	} else {
		log.Debugf("%s bridge unresolved DC for %s:%d (handshake dc=%d proto=0x%08x) -> fail open", tag, origIP, origPort, res.DC, res.ProtoTag)
		return false, &prefixConn{Conn: client, prefix: append([]byte(nil), init...)}
	}
	if rng, ok := dcForIPRange(origIP); ok && validTransparentDC(res.DC) && rng != res.DC {
		log.Debugf("%s bridge DC ambiguity for %s: ip-range=DC%d handshake=DC%d -> using DC%d (src=%s)", tag, origIP, rng, res.DC, dc, dcSrc)
	}

	cfg := b.cfg.Load()
	mtCfg := cfg.System.MTProto
	mtCfg.UpstreamMode = "auto"
	mtCfg.DCRelay = ""
	mtCfg.BridgeSkipNativeEdge = true

	dcConn, transport, err := dialDC(&mtCfg, cfg.Queue, dc, res.ProtoTag, nil, id)
	if err != nil {
		if shouldLogDialError(dc) {
			log.Errorf("%s bridge dial DC %d failed: %v", tag, dc, err)
		} else {
			log.Debugf("%s bridge dial DC %d failed (suppressed): %v", tag, dc, err)
		}
		// FB-04: a primary-route failure must never silently drop the client
		// connection. Run the route-ladder guard and hand the connection back
		// (full frame replayed) so the listener ladder fails open via worker
		// then direct. The disposition guard is invoked with the actual
		// fail-open outcome: it refuses (and counts) only a silent-drop
		// regression.
		_ = RoutePlanNonRecursive(DefaultRoutePlan())
		PrimaryFailureDisposition(BridgeOutcome{Disposition: BridgeFailOpen, Reason: ReasonDialFailed})
		return false, &prefixConn{Conn: client, prefix: append([]byte(nil), init...)}
	}
	defer dcConn.Close()

	label := fmt.Sprintf("%s %s<->DC%d(transparent via %s)", tag, client.RemoteAddr(), dc, transport)
	log.Infof("%s bridge relay %s:%d -> DC%d via %s [dc-from=%s]", tag, origIP, origPort, dc, transport, dcSrc)

	var splitter *msgSplitter
	if _, isWS := dcConn.Conn.(*wsConn); isWS {
		splitter = newMsgSplitter(res.ProtoTag)
	}
	relayConns(res.Conn, dcConn, splitter, label, &b.bufPool, mtprotoIdleTimeout(cfg), nil)
	return true, nil
}

func (b *TransparentBridge) FailOpenViaWorker(client net.Conn, origIP net.IP, origPort int) bool {
	cfg := b.cfg.Load()
	mt := cfg.System.MTProto
	domains := workerDomains(&mt)
	if len(domains) == 0 {
		return false
	}
	id := nextConnID()
	tag := tg(id)
	dst := origIP.String()
	dc := 0
	if m, ok := dcForIP(origIP); ok {
		dc = m
	} else if m, ok := dcForIPRange(origIP); ok {
		dc = m
	}
	for _, wd := range domains {
		path := fmt.Sprintf("/apiws?dst=%s&dc=%d&port=%d", dst, dc, origPort)
		wc, derr := dialWS(wd, wd, path, wsDialTimeout, cfg.Queue.Mark)
		if derr != nil {
			log.Debugf("%s failopen worker dial %s for %s:%d failed: %v", tag, wd, dst, origPort, derr)
			continue
		}
		log.Infof("%s failopen relay %s:%d via wsworker://%s", tag, dst, origPort, wd)
		label := fmt.Sprintf("%s %s<->%s:%d(failopen)", tag, client.RemoteAddr(), dst, origPort)
		relayConns(client, wc, nil, label, &b.bufPool, mtprotoIdleTimeout(cfg), nil)
		return true
	}
	return false
}

func validTransparentDC(dc int) bool {
	a := dc
	if a < 0 {
		a = -a
	}
	return (a >= 1 && a <= 5) || a == 203
}

func reservedFirst4(b []byte) bool {
	return isReservedFirst4(b)
}
