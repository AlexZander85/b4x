// H2 CONNECT carrier for the Opera data plane (masquerade chapter §7.4.4,
// stage OP-M2; reference pattern transport/fxvpn/h2tunnel.go): one
// long-lived HTTP/2 session per node carrying every target as a CONNECT
// stream.
//
// Why it matters twice over:
//
//   - masking — a browser keeps FEW long-lived TLS connections and
//     multiplexes inside them; per-dial full handshakes ("handshake burst
//     to one IP") are a robot signature. With the h2 session, the
//     ClientHello per node becomes a rare event;
//   - performance — every stream skips TCP+TLS+CONNECT setup.
//
// The session rides the SAME fingerprinted TLS stack (OP-M0/M1): the
// ClientHello is the Chrome hello; ALPN negotiates h2 with the node, and
// only then does the engine offer the h2 path (the ALPN offer is trimmed
// to http/1.1 when the h2 engine is absent — an h2 offer we cannot speak
// would break the tunnel).
package opera

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	// h2WriteBufLimit applies backpressure on the CONNECT stream writer
	// (fxvpn ring-buffer concept, simplified to a bounded buffer).
	h2WriteBufLimit = 1 << 20
)

// errH2Unavailable reports that the node did not negotiate HTTP/2 — the
// caller falls back to the HTTP/1.1 CONNECT engine.
var errH2Unavailable = errors.New("opera: node did not negotiate HTTP/2")

// negotiatedProtocol reports the ALPN-negotiated protocol over both TLS
// stacks (plain-Go and uTLS).
func negotiatedProtocol(conn net.Conn) string {
	switch t := conn.(type) {
	case *tls.Conn:
		return t.ConnectionState().NegotiatedProtocol
	case *utls.UConn:
		return t.ConnectionState().NegotiatedProtocol
	default:
		return ""
	}
}

// noopAddr satisfies the net.Conn address contract for tunnel streams
// (the addresses carry no meaning inside a multiplexed session).
type noopAddr struct{}

func (noopAddr) Network() string { return "h2-tunnel" }
func (noopAddr) String() string  { return "h2-tunnel" }

// h2Pool owns one h2 CONNECT session per node address. Concurrency-safe;
// sessions are replaced wholesale on failure (no half-open reuse).
type h2Pool struct {
	sessions sync.Map // string(addr) -> *h2Session
}

// h2Session is one live HTTP/2 CONNECT session to a node.
type h2Session struct {
	raw net.Conn
	cc  *http2.ClientConn

	closeOnce sync.Once
	closeErr  error
}

func (s *h2Session) close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.cc.Close()
		if cerr := s.raw.Close(); s.closeErr == nil {
			s.closeErr = cerr
		}
	})
	return s.closeErr
}

// open streams one CONNECT tunnel to authority through the session.
func (s *h2Session) open(parent context.Context, authority, auth string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(parent)
	body := newTunnelWriteBuffer(h2WriteBufLimit)
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+authority, body)
	if err != nil {
		cancel()
		body.fail(err)
		return nil, fmt.Errorf("opera: h2 connect request: %w", err)
	}
	req.Host = authority
	req.Header.Set("Proxy-Authorization", auth)

	resp, err := s.cc.RoundTrip(req)
	if err != nil {
		body.fail(err)
		cancel()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		status := resp.Status
		if status == "" {
			status = fmt.Sprintf("%d", resp.StatusCode)
		}
		_ = resp.Body.Close()
		body.fail(errH2Unavailable)
		cancel()
		// Same structured shape as the 1.1 engine: 407 keeps its status so
		// the credential machinery (review M2) treats h2 and 1.1 alike.
		return nil, newFailureStatus(ClassDataPlaneConnectRefused,
			fmt.Sprintf("h2 connect to %s: %s", authority, status), resp.StatusCode, nil)
	}
	return &tunnelConn{
		reader: resp.Body,
		writer: body,
		cancel: cancel,
	}, nil
}

// dial returns a tunnel to authority: via the cached session when alive,
// via a fresh session otherwise (one retry — a dead cached session must
// not fail the dial).
// tryCached opens one CONNECT stream on the CACHED session for nodeAddr
// (no TLS dial — the whole point of the multiplex). found=false means no
// cached session; found=true with err!=nil means the cached attempt FAILED
// (the session was evicted; a structured 407 must surface, a transport
// failure may fall through to a fresh dial).
func (p *h2Pool) tryCached(ctx context.Context, nodeAddr, authority, auth string) (net.Conn, error, bool) {
	cached, ok := p.sessions.Load(nodeAddr)
	if !ok {
		return nil, nil, false
	}
	sess := cached.(*h2Session)
	conn, err := sess.open(ctx, authority, auth)
	if err == nil {
		return conn, nil, true
	}
	// Transport-level failure invalidates the cached session; a structured
	// 407/etc. also invalidates it for correctness (credentials rotate
	// under it).
	p.sessions.Delete(nodeAddr)
	_ = sess.close()
	return nil, err, true
}

// establish creates a FRESH session from an already-TLS'd h2 connection
// and opens the first CONNECT stream on it.
func (p *h2Pool) establish(ctx context.Context, raw net.Conn, nodeAddr, authority, auth string) (net.Conn, error) {
	tr := &http2.Transport{
		ReadIdleTimeout:  h2ReadIdleTimeout,
		PingTimeout:      h2PingTimeout,
		WriteByteTimeout: h2WriteByteTimeout,
	}
	cc, err := tr.NewClientConn(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("opera: h2 client conn: %w", err)
	}
	sess := &h2Session{raw: raw, cc: cc}
	actual, loaded := p.sessions.LoadOrStore(nodeAddr, sess)
	if loaded {
		_ = sess.close() // lost the race; use the winner
		sess = actual.(*h2Session)
		return sess.open(ctx, authority, auth)
	}
	return sess.open(ctx, authority, auth)
}

// Timeouts (fxvpn h2tunnel parity): idle liveness via PING, bounded writes.
const (
	h2ReadIdleTimeout  = 30 * time.Second
	h2PingTimeout      = 15 * time.Second
	h2WriteByteTimeout = 30 * time.Second
)

// tunnelWriteBuffer is a bounded read-write pipe serving as the CONNECT
// request body AND the tunnel writer (io.Pile replacement per fxvpn:
// writes buffer up to the limit, block under backpressure, fail after
// close).
type tunnelWriteBuffer struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  []byte
	max  int

	closed   bool
	closeErr error
}

func newTunnelWriteBuffer(max int) *tunnelWriteBuffer {
	b := &tunnelWriteBuffer{max: max}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *tunnelWriteBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.buf) == 0 && !b.closed {
		b.cond.Wait()
	}
	if len(b.buf) == 0 {
		if b.closeErr != nil {
			return 0, b.closeErr
		}
		return 0, io.EOF
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	b.cond.Broadcast() // writers may proceed under the backpressure limit
	return n, nil
}

func (b *tunnelWriteBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.buf)+len(p) > b.max && !b.closed {
		b.cond.Wait()
	}
	if b.closed {
		return 0, fmt.Errorf("opera: tunnel write: %w", b.closeErr)
	}
	b.buf = append(b.buf, p...)
	b.cond.Broadcast()
	return len(p), nil
}

// Close completes the write half (clean EOF to the tunnel reader).
func (b *tunnelWriteBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		b.cond.Broadcast()
	}
	return nil
}

// fail aborts both halves (transport-level failure downstream).
func (b *tunnelWriteBuffer) fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		if b.closeErr == nil {
			b.closeErr = err
		}
		b.cond.Broadcast()
	}
}

// tunnelConn adapts one established h2 CONNECT relay to net.Conn
// (fxvpn parity: deadlines are not supported by HTTP/2 CONNECT tunnel
// streams).
type tunnelConn struct {
	reader io.Reader
	writer *tunnelWriteBuffer
	cancel context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

func (c *tunnelConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *tunnelConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *tunnelConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		if cl, ok := c.reader.(interface{ Close() error }); ok {
			_ = cl.Close()
		}
		c.closeErr = c.writer.Close()
	})
	return c.closeErr
}

func (c *tunnelConn) LocalAddr() net.Addr                { return noopAddr{} }
func (c *tunnelConn) RemoteAddr() net.Addr               { return noopAddr{} }
func (c *tunnelConn) SetDeadline(t time.Time) error      { return errH2DeadlineUnsupported }
func (c *tunnelConn) SetReadDeadline(t time.Time) error  { return errH2DeadlineUnsupported }
func (c *tunnelConn) SetWriteDeadline(t time.Time) error { return errH2DeadlineUnsupported }

// errH2DeadlineUnsupported mirrors fxvpn errTunnelDeadline: HTTP/2 CONNECT
// tunnel streams do not support deadlines (fxvpn h2tunnel parity).
var errH2DeadlineUnsupported = errors.New("opera: deadlines are not supported for HTTP/2 CONNECT tunnel streams")
