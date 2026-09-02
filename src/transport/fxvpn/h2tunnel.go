// H2 CONNECT carrier (reference cmd/proxy-demo/main.go:2452-2606, protocol
// facts verified against its sources): one TLS connection (ALPN h2, MinVer
// 1.2) carrying one long-lived http2.ClientConn; every target gets a
// CONNECT stream with Proxy-Authorization: Bearer <proxy pass>; a 2xx turns
// the stream into a raw bidirectional relay. Keepalive PING notices silently
// dropped sessions while idle; UpdateToken renews the bearer IN PLACE.
package fxvpn

import (
        "context"
        "crypto/tls"
        "errors"
        "fmt"
        "io"
        "net"
        "net/http"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "golang.org/x/net/http2"
)

const (
        h2KeepAliveInterval      = 10 * time.Second
        h2KeepAlivePingBudget    = 15 * time.Second
        h2TransportReadIdle      = 30 * time.Second
        h2TransportPingTimeout   = 15 * time.Second
        h2TransportWriteByteTime = 30 * time.Second

        tunnelWriteBufSize = 1 << 20
)

var errH2Unavailable = errors.New("fxvpn: proxy did not negotiate HTTP/2")

// DialH2 establishes one upstream H2 CONNECT session.
// Masquerade FX-M1: the ClientHello producer follows MasqueradeSettings —
// "firefox" dials TCP and handshakes with the uTLS Firefox profile
// (WebPKI verification preserved through the callback); "none" keeps the
// plain-Go path with the FX-M0 tuning.
func DialH2(ctx context.Context, cfg TunnelConfig) (*H2Tunnel, error) {
        cfg.fillDefaults()
        authority := cfg.Authority()

        tlsCfg := &tls.Config{
                ServerName: cfg.Host,
                MinVersion: tls.VersionTLS12,
                NextProtos: []string{"h2"},
        }
        if cfg.TLS != nil {
                tlsCfg = cfg.TLS.Clone()
                tlsCfg.MinVersion = tls.VersionTLS12
                tlsCfg.NextProtos = []string{"h2"}
                if tlsCfg.ServerName == "" {
                        tlsCfg.ServerName = cfg.Host
                }
        }
        // Masquerade §7.4.3: Firefox cipher/curve offer on the H2 handshake
        // (the plain-Go rung; the uTLS rung carries its own profile).
        cfg.Masquerade.ApplyHelloShaping(tlsCfg)

        // The handshake itself is bounded by the handshake budget (the TCP
        // dial timeout alone would not cover a stuck TLS flight).
        hsCtx := ctx
        if _, hasDeadline := ctx.Deadline(); !hasDeadline {
                var hcancel context.CancelFunc
                hsCtx, hcancel = context.WithTimeout(ctx, cfg.HandshakeBudget)
                defer hcancel()
        }

        var raw net.Conn
        if cfg.Masquerade.fingerprintActive() {
                tconn, derr := cfg.Policy.dialTCP(ctx, "tcp", authority, cfg.HandshakeBudget)
                if derr != nil {
                        return nil, fmt.Errorf("fxvpn: h2 dial %s: %w", authority, derr)
                }
                uc, uerr := dialUTLSClient(hsCtx, tconn, cfg.Host, cfg.Masquerade, verifyWebPKIUTLS(cfg.Host, tlsCfg.RootCAs, tlsCfg.InsecureSkipVerify))
                if uerr != nil {
                        _ = tconn.Close()
                        return nil, fmt.Errorf("fxvpn: h2 utls %s: %w", authority, uerr)
                }
                if got := uc.ConnectionState().NegotiatedProtocol; got != "h2" {
                        _ = uc.Close()
                        return nil, errH2Unavailable
                }
                raw = uc
        } else {
                // Plain-Go rung: TLS straight over the policy TCP dial (direct
                // or carrier-nested, FX-M2).
                raw0, derr := cfg.Policy.dialTCP(ctx, "tcp", authority, cfg.HandshakeBudget)
                if derr != nil {
                        return nil, fmt.Errorf("fxvpn: h2 dial %s: %w", authority, derr)
                }
                tc := tls.Client(raw0, tlsCfg)
                if derr := tc.HandshakeContext(hsCtx); derr != nil {
                        _ = raw0.Close()
                        return nil, fmt.Errorf("fxvpn: h2 dial %s: %w", authority, derr)
                }
                if tc.ConnectionState().NegotiatedProtocol != "h2" {
                        _ = tc.Close()
                        return nil, errH2Unavailable
                }
                raw = tc
        }

        tr := &http2.Transport{
                ReadIdleTimeout:  h2TransportReadIdle,
                PingTimeout:      h2TransportPingTimeout,
                WriteByteTimeout: h2TransportWriteByteTime,
        }
        cc, err := tr.NewClientConn(raw)
        if err != nil {
                _ = raw.Close()
                return nil, fmt.Errorf("fxvpn: h2 client conn %s: %w", authority, err)
        }

        kaCtx, stop := context.WithCancel(context.Background())
        s := &H2Tunnel{
                raw:           raw,
                cc:            cc,
                edgeAuthority: authority,
                cfg:           cfg,
                token:         cfg.Token,
                stopKeepAlive: stop,
        }
        s.alive.Store(true)
        go s.runKeepAlive(kaCtx)
        return s, nil
}

// H2Tunnel is one live upstream HTTP/2 CONNECT session. raw is either a
// *tls.Conn (plain-Go rung) or a *utls.UConn (Firefox fingerprint rung) —
// both are net.Conn and both closed identically.
type H2Tunnel struct {
        raw           net.Conn
        cc            *http2.ClientConn
        edgeAuthority string
        cfg           TunnelConfig

        tokenMu sync.RWMutex
        token   string

        health        failureTracker
        closeOnce     sync.Once
        closeErr      error
        alive         atomic.Bool
        stopKeepAlive context.CancelFunc
}

// runKeepAlive pings periodically so a silently dropped session is noticed
// while idle rather than at the next client dial.
func (s *H2Tunnel) runKeepAlive(ctx context.Context) {
        ticker := time.NewTicker(h2KeepAliveInterval)
        defer ticker.Stop()
        for {
                select {
                case <-ctx.Done():
                        return
                case <-ticker.C:
                        pingCtx, cancel := context.WithTimeout(ctx, h2KeepAlivePingBudget)
                        err := s.cc.Ping(pingCtx)
                        cancel()
                        if err == nil {
                                continue
                        }
                        if ctx.Err() != nil {
                                return
                        }
                        s.alive.Store(false)
                        return
                }
        }
}

// IsAlive reports whether this session can carry new tunnels.
func (s *H2Tunnel) IsAlive() bool {
        return s.alive.Load() && s.cc.CanTakeNewRequest()
}

// OpenTunnel opens one CONNECT relay to authority.
//
// TIME-BUDGET CONTRACT (review F1): the OpenBudget bounds ONE CONNECT round
// trip, NOT the relay lifetime. The request therefore rides a plain
// WithCancel context and the budget is enforced by a manual timer that is
// STOPPED as soon as the 2xx arrives — x/net/http2 keeps the stream bound
// to the request context, so a deadline left on it would RST_STREAM every
// long-lived relay (ssh/telnet/downloads) once the budget fired (~20s).
// tunnelConn keeps only cancel (immediate teardown on Close).
func (s *H2Tunnel) OpenTunnel(parent context.Context, authority string) (net.Conn, error) {
        octx, cancel := context.WithCancel(parent)
        budget := &openBudget{cancel: cancel}
        budget.arm(s.cfg.OpenBudget)

        reqBody := newTunnelWriteBuffer(tunnelWriteBufSize)
        req, err := http.NewRequestWithContext(octx, http.MethodConnect, "http://"+authority, reqBody)
        if err != nil {
                budget.disarm()
                cancel()
                reqBody.failRead(io.ErrClosedPipe)
                return nil, err
        }
        req.Host = authority
        req.URL.Host = s.edgeAuthority
        req.Header.Set("Proxy-Authorization", "Bearer "+s.bearerToken())

        resp, err := s.cc.RoundTrip(req)
        if err != nil {
                reqBody.failRead(io.ErrClosedPipe)
                budget.disarm()
                cancel()
                kind := classifyOpenFailure(err)
                if kind == "" && budget.fired.Load() {
                        kind = "timeout" // manual budget, not a parent deadline
                }
                return nil, s.health.observe(authority, kind, err)
        }
        if resp.StatusCode < 200 || resp.StatusCode > 299 {
                body := readAllLimited(resp.Body)
                _ = resp.Body.Close()
                reqBody.failRead(io.ErrClosedPipe)
                budget.disarm()
                cancel()
                rej := &ConnectRejectedError{StatusCode: resp.StatusCode, Status: resp.Status, Body: strings.TrimSpace(string(body))}
                var kind string
                if rej.StatusCode == http.StatusBadGateway {
                        kind = "bad-gateway"
                }
                return nil, s.health.observe(authority, kind, rej)
        }
        if !budget.disarm() {
                // The budget fired between the 2xx and the disarm: the stream is
                // already being torn down — report the timeout honestly instead of
                // handing out a dying relay.
                reqBody.failRead(io.ErrClosedPipe)
                cancel()
                return nil, s.health.observe(authority, "timeout",
                        fmt.Errorf("fxvpn: connect %s open budget fired at establishment", authority))
        }
        s.health.observe(authority, "", nil)
        return &tunnelConn{reader: resp.Body, writer: reqBody, cancel: cancel}, nil
}

// openBudget is the manual establishment timer of OpenTunnel (review F1):
// the context handed to the HTTP request stays cancel-only; this type owns
// the OpenBudget deadline and reports whether it fired.
type openBudget struct {
        cancel context.CancelFunc
        timer  *time.Timer
        fired  atomic.Bool
}

// arm starts the establishment timer: on expiry it publishes `fired` and
// cancels the request context (the RoundTrip fails with a canceled context,
// classified as timeout via `fired`).
func (g *openBudget) arm(budget time.Duration) {
        g.timer = time.AfterFunc(budget, func() {
                g.fired.Store(true)
                g.cancel()
        })
}

// disarm stops the establishment timer. It reports false when the budget
// already fired (or its callback raced past the stop) — the caller must not
// hand out the relay in that case.
func (g *openBudget) disarm() bool {
        if g.fired.Load() {
                return false
        }
        if g.timer.Stop() {
                return true
        }
        // Stop() lost the race with the callback start; the callback publishes
        // `fired` first thing, so a false read means it was already stopped.
        return !g.fired.Load()
}

// classifyOpenFailure maps transport-level failures onto tracker kinds.
func classifyOpenFailure(err error) string {
        var ne net.Error
        if errors.As(err, &ne) && ne.Timeout() {
                return "timeout"
        }
        if errors.Is(err, context.DeadlineExceeded) {
                return "timeout"
        }
        return ""
}

func (s *H2Tunnel) bearerToken() string {
        s.tokenMu.RLock()
        defer s.tokenMu.RUnlock()
        return s.token
}

// UpdateToken swaps the proxy pass in place (renew lead 2 min before exp).
func (s *H2Tunnel) UpdateToken(token string) error {
        if strings.TrimSpace(token) == "" {
                return fmt.Errorf("fxvpn: empty proxy session token")
        }
        s.tokenMu.Lock()
        s.token = token
        s.tokenMu.Unlock()
        return nil
}

// Close tears the session down once.
func (s *H2Tunnel) Close() error {
        s.closeOnce.Do(func() {
                s.alive.Store(false)
                if s.stopKeepAlive != nil {
                        s.stopKeepAlive()
                }
                s.closeErr = s.cc.Close()
                if cerr := s.raw.Close(); s.closeErr == nil {
                        s.closeErr = cerr
                }
        })
        return s.closeErr
}

// ---- tunnelConn + ring-buffer request body (reference main.go:2796+) ----

// tunnelConn adapts one established relay to net.Conn. Deadlines are not
// supported by HTTP CONNECT tunnel streams (reference errTunnelDeadline).
type tunnelConn struct {
        reader io.Reader
        writer io.Writer
        cancel context.CancelFunc

        closeOnce sync.Once
        closeErr  error
}

func (c *tunnelConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *tunnelConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *tunnelConn) Close() error {
        c.closeOnce.Do(func() {
                if cl, ok := c.reader.(interface{ Close() error }); ok {
                        _ = cl.Close()
                }
                if cl, ok := c.writer.(interface{ Close() error }); ok {
                        c.closeErr = cl.Close()
                }
                if c.cancel != nil {
                        c.cancel()
                }
        })
        return c.closeErr
}

// CloseWrite half-closes the send side (request body EOF => END_STREAM)
// while keeping the receive side readable: the standard proxy-relay
// contract for echo-style peers (reference half-close drain semantics).
func (c *tunnelConn) CloseWrite() error {
        if cl, ok := c.writer.(interface{ Close() error }); ok {
                return cl.Close()
        }
        return nil
}

func (c *tunnelConn) LocalAddr() net.Addr              { return tunnelAddr{} }
func (c *tunnelConn) RemoteAddr() net.Addr             { return tunnelAddr{} }
func (c *tunnelConn) SetDeadline(time.Time) error      { return errTunnelDeadline }
func (c *tunnelConn) SetReadDeadline(time.Time) error  { return errTunnelDeadline }
func (c *tunnelConn) SetWriteDeadline(time.Time) error { return errTunnelDeadline }

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "fxvpn-tunnel" }
func (tunnelAddr) String() string  { return "fxvpn-relay" }

var errTunnelDeadline = errors.New("fxvpn: deadlines are not supported for HTTP CONNECT tunnel streams")

// tunnelWriteBuffer is a bounded, concurrency-safe ring buffer used as the
// request body of a CONNECT tunnel. It replaces io.Pipe, whose every write
// blocks until a reader consumes it: a writer can run ahead of the HTTP
// transport by up to the buffer size (reference throughput fix).
type tunnelWriteBuffer struct {
        mu       sync.Mutex
        notEmpty *sync.Cond
        notFull  *sync.Cond
        buf      []byte
        n        int
        off      int
        closed   bool
        readErr  error
}

func newTunnelWriteBuffer(size int) *tunnelWriteBuffer {
        if size < 1 {
                size = tunnelWriteBufSize
        }
        b := &tunnelWriteBuffer{buf: make([]byte, size)}
        b.notEmpty = sync.NewCond(&b.mu)
        b.notFull = sync.NewCond(&b.mu)
        return b
}

// Read drains buffered data, blocking while the buffer is empty and still
// open. Review L5: once data is available the read drains EVERYTHING the
// ring currently holds, walking across the wrap point — the old
// contiguous-tail copy returned a short read in the middle of the ring
// (legal io.Reader, but the http2 request-body path dislikes it). The
// streaming contract is unchanged: the read returns as soon as the buffered
// data is drained; it does NOT wait to fill p.
func (b *tunnelWriteBuffer) Read(p []byte) (int, error) {
        b.mu.Lock()
        defer b.mu.Unlock()
        for b.n == 0 && b.readErr == nil && !b.closed {
                b.notEmpty.Wait()
        }
        if b.n == 0 {
                if b.readErr != nil {
                        return 0, b.readErr
                }
                return 0, io.EOF
        }
        total := 0
        for total < len(p) && b.n > 0 {
                end := b.off + b.n
                if end > len(b.buf) {
                        end = len(b.buf)
                }
                n := copy(p[total:], b.buf[b.off:end])
                b.off = (b.off + n) % len(b.buf)
                b.n -= n
                total += n
        }
        b.notFull.Broadcast()
        return total, nil
}

// Write blocks only while the buffer is full.
func (b *tunnelWriteBuffer) Write(p []byte) (int, error) {
        b.mu.Lock()
        defer b.mu.Unlock()
        total := 0
        for len(p) > 0 {
                for b.n == len(b.buf) && b.readErr == nil && !b.closed {
                        b.notFull.Wait()
                }
                if b.readErr != nil {
                        return total, b.readErr
                }
                if b.closed {
                        return total, io.ErrClosedPipe
                }
                space := len(b.buf) - b.n
                head := (b.off + b.n) % len(b.buf)
                writable := len(b.buf) - head
                if space < writable {
                        writable = space
                }
                if writable > len(p) {
                        writable = len(p)
                }
                copy(b.buf[head:], p[:writable])
                b.n += writable
                p = p[writable:]
                total += writable
                b.notEmpty.Broadcast()
        }
        return total, nil
}

// Close signals end of stream; buffered data stays readable so a
// half-closed tunnel still flushes what the client already wrote.
func (b *tunnelWriteBuffer) Close() error {
        b.mu.Lock()
        defer b.mu.Unlock()
        if b.closed {
                return nil
        }
        b.closed = true
        b.notEmpty.Broadcast()
        b.notFull.Broadcast()
        return nil
}

// failRead aborts blocked readers (used when the CONNECT fails early).
func (b *tunnelWriteBuffer) failRead(err error) {
        b.mu.Lock()
        defer b.mu.Unlock()
        if b.readErr == nil {
                b.readErr = err
        }
        b.notEmpty.Broadcast()
}
