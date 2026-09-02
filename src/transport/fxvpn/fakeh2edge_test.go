package fxvpn

import (
        "bufio"
        "bytes"
        "context"
        "crypto/tls"
        "errors"
        "io"
        "net"
        "net/http"
        "net/http/httptest"
        "strconv"
        "strings"
        "sync"
        "testing"
        "time"
)

// fakeH2Edge is a TLS+HTTP/2 stand speaking the CONNECT dialect with a
// behavior matrix (design FX2): happy echo / non-2xx statuses / silent-drop
// (200 but no data) / teardown mid-stream / wrong-JWT 407 / hang-CONNECT /
// quota-429-on-CONNECT. Go's http server exposes the CONNECT relay as
// req.Body (inbound) + ResponseWriter (outbound).
type fakeH2Edge struct {
        srv *httptest.Server

        mu            sync.Mutex
        mode          string // echo|silent|teardown|hang
        status        int    // CONNECT answer status when mode != status-driven
        fixedStatus   int    // when >0: always answer this status
        expectToken   string // when set: mismatch answers 407
        tracePayload  string // served by the TLS mini-origin for the exit host
        probeTLS      *tls.Config
        delay         time.Duration // "delayed" mode: echo hold past the open budget
        connects      int
        lastAuth      string
        lastAuthority string
}

// relayPipe adapts a CONNECT relay (request body in / response writer out)
// to net.Conn so the fake origin can terminate TLS inside the tunnel. Every
// write flushes: h2 response buffering would otherwise withhold TLS
// handshake flights and deadlock the probe.
type relayPipe struct {
        r io.Reader
        w io.Writer
}

func (p relayPipe) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p relayPipe) Write(b []byte) (int, error) {
        n, err := p.w.Write(b)
        if f, ok := p.w.(http.Flusher); ok {
                f.Flush()
        }
        return n, err
}

func (p relayPipe) Close() error                     { return nil }
func (p relayPipe) LocalAddr() net.Addr              { return tunnelAddr{} }
func (p relayPipe) RemoteAddr() net.Addr             { return tunnelAddr{} }
func (p relayPipe) SetDeadline(time.Time) error      { return nil }
func (p relayPipe) SetReadDeadline(time.Time) error  { return nil }
func (p relayPipe) SetWriteDeadline(time.Time) error { return nil }

func newFakeH2Edge(t *testing.T) *fakeH2Edge {
        t.Helper()
        e := &fakeH2Edge{mode: "echo"}
        cert := newSelfSignedCert(t)
        e.probeTLS = &tls.Config{Certificates: []tls.Certificate{cert}}
        // Plain HandlerFunc, NOT ServeMux: mux answers CONNECT (empty path)
        // with 301 redirects before our handler ever runs.
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                e.mu.Lock()
                e.connects++
                e.lastAuth = r.Header.Get("Proxy-Authorization")
                e.lastAuthority = r.Host
                mode, status, fixed, expect, trace := e.mode, e.status, e.fixedStatus, e.expectToken, e.tracePayload
                e.mu.Unlock()

                if r.Method != http.MethodConnect {
                        w.WriteHeader(http.StatusNotFound)
                        return
                }
                if expect != "" && r.Header.Get("Proxy-Authorization") != "Bearer "+expect {
                        w.WriteHeader(http.StatusProxyAuthRequired)
                        _, _ = io.WriteString(w, "wrong jwt")
                        return
                }
                if fixed > 0 {
                        w.WriteHeader(fixed)
                        _, _ = io.WriteString(w, "edge says no")
                        return
                }
                if status != 200 && status != 0 {
                        w.WriteHeader(status)
                        _, _ = io.WriteString(w, "edge says no")
                        return
                }
                if mode == "hang" {
                        // Hang BEFORE any response byte: the client open budget must fire.
                        <-r.Context().Done()
                        return
                }
                w.WriteHeader(http.StatusOK)
                flusher, _ := w.(http.Flusher)
                if flusher != nil {
                        flusher.Flush()
                }
                delay := time.Duration(0)
                e.mu.Lock()
                delay = e.delay
                e.mu.Unlock()

                switch {
                case e.probeTLS != nil && strings.HasPrefix(r.Host, exitProbeHost+":"):
                        // Mini-origin: terminate TLS INSIDE the relay exactly like the
                        // real trace endpoint would behind CONNECT, answer once, close.
                        origin := tls.Server(relayPipe{r: r.Body, w: w}, e.probeTLS)
                        _ = origin.SetDeadline(time.Now().Add(5 * time.Second))
                        if herr := origin.HandshakeContext(r.Context()); herr != nil {
                        } else {
                                if _, rerr := http.ReadRequest(bufio.NewReader(origin)); rerr != nil {
                                } else {
                                        body := trace
                                        resp := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
                                        _, _ = origin.Write([]byte(resp))
                                }
                        }
                        _ = origin.Close()
                        return
                case mode == "silent":
                        return // headers only; stream ends => client reads EOF
                case mode == "delayed":
                        // Review F1 regression stand: the edge reads the client
                        // bytes, HOLDS the echo past the open budget, then answers.
                        // The relay must survive the budget — only the CONNECT round
                        // trip is bounded by it. The tail copy rides relayPipe so
                        // every write flushes (no half-close: the relay stays open).
                        buf := make([]byte, echoChunkLen)
                        n, _ := io.ReadFull(r.Body, buf)
                        time.Sleep(delay)
                        if _, err := w.Write(buf[:n]); err == nil && flusher != nil {
                                flusher.Flush()
                        }
                        _, _ = io.Copy(relayPipe{r: r.Body, w: w}, r.Body)
                case mode == "teardown":
                        buf := make([]byte, echoChunkLen)
                        n, _ := io.ReadFull(r.Body, buf)
                        _, _ = w.Write(buf[:n])
                        if flusher != nil {
                                flusher.Flush()
                        }
                        panic(http.ErrAbortHandler) // reset the stream mid-relay
                default: // echo
                        _, _ = io.Copy(w, r.Body)
                }
        })

        srv := httptest.NewUnstartedServer(handler)
        srv.EnableHTTP2 = true
        srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}
        srv.StartTLS()
        t.Cleanup(srv.Close)
        e.srv = srv
        return e
}

func (e *fakeH2Edge) addr() (string, int) {
        host, portStr, _ := net.SplitHostPort(e.srv.Listener.Addr().String())
        port, err := strconv.Atoi(portStr)
        if err != nil {
                return host, 0
        }
        return host, port
}

func (e *fakeH2Edge) setBehavior(mode string, fixedStatus int, expectToken string) {
        e.mu.Lock()
        defer e.mu.Unlock()
        e.mode = mode
        e.fixedStatus = fixedStatus
        e.expectToken = expectToken
}

// setDelay arms the "delayed" behavior: the echo is held for d after the
// CONNECT is already established (review F1 regression stand).
func (e *fakeH2Edge) setDelay(d time.Duration) {
        e.mu.Lock()
        defer e.mu.Unlock()
        e.mode = "delayed"
        e.delay = d
}

func (e *fakeH2Edge) counters() (int, string, string) {
        e.mu.Lock()
        defer e.mu.Unlock()
        return e.connects, e.lastAuth, e.lastAuthority
}

func dialH2Test(t *testing.T, e *fakeH2Edge, token string) *H2Tunnel {
        t.Helper()
        host, port := e.addr()
        s, err := DialH2(context.Background(), testTunnelConfig(host, port, token))
        if err != nil {
                t.Fatalf("DialH2: %v", err)
        }
        t.Cleanup(func() { _ = s.Close() })
        return s
}

// ---- matrix -----------------------------------------------------------------

func TestH2HappyEchoBidirectional(t *testing.T) {
        e := newFakeH2Edge(t)
        s := dialH2Test(t, e, "jwt-1")

        conn, err := s.OpenTunnel(context.Background(), "target.example:443")
        if err != nil {
                t.Fatalf("OpenTunnel: %v", err)
        }
        defer conn.Close()

        payload := []byte("hello through the reserve transport")
        if _, err := conn.Write(payload); err != nil {
                t.Fatalf("write: %v", err)
        }
        if err := halfClose(conn); err != nil {
                t.Fatalf("close write: %v", err)
        }
        got := make([]byte, len(payload))
        if _, err := io.ReadFull(conn, got); err != nil {
                t.Fatalf("read: %v", err)
        }
        if string(got) != string(payload) {
                t.Fatalf("echo mismatch: %q", got)
        }

        // Bearer reached the edge.
        if _, auth, _ := e.counters(); auth != "Bearer jwt-1" {
                t.Fatalf("bearer = %q", auth)
        }
}

func TestH2ChunkedEchoThroughRingBuffer(t *testing.T) {
        e := newFakeH2Edge(t)
        s := dialH2Test(t, e, "jwt-1")

        conn, err := s.OpenTunnel(context.Background(), "bulk.example:443")
        if err != nil {
                t.Fatalf("OpenTunnel: %v", err)
        }
        defer conn.Close()

        payload := make([]byte, 256*1024)
        for i := range payload {
                payload[i] = byte(i * 7)
        }
        go func() {
                _, _ = conn.Write(payload)
                _ = halfClose(conn)
        }()
        got, err := io.ReadAll(io.LimitReader(conn, int64(len(payload))))
        if err != nil {
                t.Fatalf("read: %v", err)
        }
        if len(got) != len(payload) {
                t.Fatalf("len = %d want %d", len(got), len(payload))
        }
        for i := range payload {
                if got[i] != payload[i] {
                        t.Fatalf("byte %d mismatch", i)
                }
        }
}

func TestH2502ThreeDistinctTargetsSessionUnhealthy(t *testing.T) {
        e := newFakeH2Edge(t)
        e.setBehavior("", http.StatusBadGateway, "")
        s := dialH2Test(t, e, "jwt-1")

        var last error
        for _, target := range []string{"a.example:80", "b.example:80", "c.example:80"} {
                _, last = s.OpenTunnel(context.Background(), target)
                var rej *ConnectRejectedError
                if !asConnectRejected(last, &rej) || rej.StatusCode != 502 {
                        t.Fatalf("%s: want 502 rejected, got %v", target, last)
                }
        }
        if !isUnhealthy(last) {
                t.Fatalf("third distinct 502 must trip session unhealthy, got %v", last)
        }
        // A success resets the tracker.
        e.setBehavior("echo", 0, "")
        if _, err := s.OpenTunnel(context.Background(), "d.example:80"); err != nil {
                t.Fatalf("recovered open: %v", err)
        }
        // Fresh streak: the THIRD distinct target trips again (e,f,g).
        e.setBehavior("", http.StatusBadGateway, "")
        var third error
        for _, target := range []string{"e.example:80", "f.example:80", "g.example:80"} {
                _, third = s.OpenTunnel(context.Background(), target)
        }
        if !isUnhealthy(third) {
                t.Fatalf("third distinct 502 after reset must trip unhealthy again: %v", third)
        }
}

func TestH2WrongJWTIs407NotUnhealthy(t *testing.T) {
        e := newFakeH2Edge(t)
        e.setBehavior("", 0, "the-real-token")
        s := dialH2Test(t, e, "forged-token")

        for i := 0; i < 5; i++ {
                _, err := s.OpenTunnel(context.Background(), "x.example:80")
                var rej *ConnectRejectedError
                if !asConnectRejected(err, &rej) || rej.StatusCode != http.StatusProxyAuthRequired {
                        t.Fatalf("want 407, got %v", err)
                }
                if isUnhealthy(err) {
                        t.Fatal("account-level rejection must not trip session health")
                }
        }
}

func TestH2Quota429OnConnect(t *testing.T) {
        e := newFakeH2Edge(t)
        e.setBehavior("", http.StatusTooManyRequests, "")
        s := dialH2Test(t, e, "jwt-1")

        _, err := s.OpenTunnel(context.Background(), "y.example:80")
        var rej *ConnectRejectedError
        if !asConnectRejected(err, &rej) || !rej.IsQuota() {
                t.Fatalf("want quota-flagged 429, got %v", err)
        }
}

func TestH2HangConnectBudgetFires(t *testing.T) {
        e := newFakeH2Edge(t)
        e.setBehavior("hang", 0, "")
        s := dialH2Test(t, e, "jwt-1")

        start := time.Now()
        _, err := s.OpenTunnel(context.Background(), "slow.example:80")
        if err == nil {
                t.Fatal("budget must fire on hang")
        }
        if elapsed := time.Since(start); elapsed > 6*time.Second {
                t.Fatalf("budget too slow: %v", elapsed)
        }
}

func TestH2SilentDropReadsEOFFast(t *testing.T) {
        e := newFakeH2Edge(t)
        e.setBehavior("silent", 0, "")
        s := dialH2Test(t, e, "jwt-1")

        conn, err := s.OpenTunnel(context.Background(), "quiet.example:443")
        if err != nil {
                t.Fatalf("200 expected for silent-drop scenario: %v", err)
        }
        defer conn.Close()

        done := make(chan error, 1)
        go func() {
                buf := make([]byte, 16)
                _, err := conn.Read(buf)
                done <- err
        }()
        select {
        case err := <-done:
                if err == nil {
                        t.Fatal("expected EOF/error from silent edge")
                }
        case <-time.After(5 * time.Second):
                t.Fatal("silent drop must surface immediately, not hang")
        }
}

func TestH2TeardownMidStreamErrors(t *testing.T) {
        e := newFakeH2Edge(t)
        e.setBehavior("teardown", 0, "")
        s := dialH2Test(t, e, "jwt-1")

        conn, err := s.OpenTunnel(context.Background(), "rip.example:443")
        if err != nil {
                t.Fatalf("open: %v", err)
        }
        defer conn.Close()

        // The teardown stand echoes exactly echoChunkLen bytes of the first
        // inbound chunk before killing the stream.
        chunk := []byte("feed-the-teardown-echo")
        if _, werr := conn.Write(chunk); werr != nil {
                t.Fatalf("write: %v", werr)
        }
        buf := make([]byte, echoChunkLen)
        if _, err := io.ReadFull(conn, buf); err != nil {
                t.Fatalf("first chunk should arrive before teardown: %v", err)
        }
        _ = halfClose(conn)
        errCh := make(chan error, 1)
        go func() {
                _, err := conn.Read(make([]byte, 32))
                errCh <- err
        }()
        select {
        case err := <-errCh:
                if err == nil {
                        t.Fatal("teardown must surface as read error")
                }
        case <-time.After(5 * time.Second):
                t.Fatal("teardown must not hang reads")
        }
}

func TestH2UpdateTokenAppliesToNextTunnel(t *testing.T) {
        e := newFakeH2Edge(t)
        e.setBehavior("echo", 0, "")
        s := dialH2Test(t, e, "jwt-old")

        c1, err := s.OpenTunnel(context.Background(), "one.example:80")
        if err != nil {
                t.Fatalf("tunnel1: %v", err)
        }
        _ = c1.Close()

        if err := s.UpdateToken("jwt-new"); err != nil {
                t.Fatalf("UpdateToken: %v", err)
        }
        c2, err := s.OpenTunnel(context.Background(), "two.example:80")
        if err != nil {
                t.Fatalf("tunnel2 after renew: %v", err)
        }
        _ = c2.Close()

        if _, auth, _ := e.counters(); auth != "Bearer jwt-new" {
                t.Fatalf("bearer after renew = %q", auth)
        }
        if s.bearerToken() != "jwt-new" {
                t.Fatal("session token not swapped in place")
        }
}

// TestH2RelayOutlivesOpenBudget pins review F1: the OpenBudget bounds the
// CONNECT round trip, NOT the relay lifetime. The edge holds the echo past
// the budget; a relay bound to a deadline-carrying request context would be
// RST_STREAMed by x/net/http2 the moment the budget fired and the exchange
// would die mid-stream.
func TestH2RelayOutlivesOpenBudget(t *testing.T) {
        e := newFakeH2Edge(t)
        e.setDelay(1200 * time.Millisecond) // echo answers AFTER the budget
        host, port := e.addr()

        cfg := testTunnelConfig(host, port, "jwt-1")
        cfg.OpenBudget = 500 * time.Millisecond
        s, err := DialH2(context.Background(), cfg)
        if err != nil {
                t.Fatalf("DialH2: %v", err)
        }
        t.Cleanup(func() { _ = s.Close() })

        conn, err := s.OpenTunnel(context.Background(), "longlived.example:443")
        if err != nil {
                t.Fatalf("OpenTunnel: %v", err)
        }
        defer conn.Close()

        payload := bytes.Repeat([]byte("A"), echoChunkLen)
        if _, err := conn.Write(payload); err != nil {
                t.Fatalf("write before budget: %v", err)
        }
        // Wait past the establishment budget: with the F1 defect the stream
        // is reset here and the read below fails.
        time.Sleep(700 * time.Millisecond)
        got := make([]byte, len(payload))
        if _, err := io.ReadFull(conn, got); err != nil {
                t.Fatalf("relay died at/after open budget: %v", err)
        }
        if !bytes.Equal(got, payload) {
                t.Fatal("echo mismatch after budget")
        }
        // The relay keeps serving after the delayed exchange too.
        if _, err := conn.Write([]byte("ping")); err != nil {
                t.Fatalf("second write: %v", err)
        }
        if _, err := io.ReadFull(conn, got[:4]); err != nil {
                t.Fatalf("second exchange: %v", err)
        }
}

// ---- helpers shared by carrier tests ----------------------------------------

func asConnectRejected(err error, target **ConnectRejectedError) bool {
        var rej *ConnectRejectedError
        if errors.As(err, &rej) {
                *target = rej
                return true
        }
        return false
}

func isUnhealthy(err error) bool {
        return errors.Is(err, ErrSessionUnhealthy)
}
