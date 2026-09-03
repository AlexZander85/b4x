package fxvpn

import (
        "context"
        "crypto/tls"
        "io"
        "net"
        "net/http"
        "strconv"
        "strings"
        "sync"
        "testing"
        "time"

        "github.com/quic-go/quic-go"
)

// fakeH3Edge is a QUIC/H3 stand speaking the plain-CONNECT dialect with the
// same behavior matrix as the H2 stand. Server side is raw quic-go: control
// stream SETTINGS first, then one bi-stream per CONNECT.
type fakeH3Edge struct {
        ln *quic.Listener

        mu            sync.Mutex
        mode          string // echo|silent|teardown|hang|kill
        fixedStatus   int
        expectToken   string
        tracePayload  string
        connects      int
        connAccepts   int
        lastAuth      string
        lastAuthority string
}

func newFakeH3Edge(t *testing.T) *fakeH3Edge {
        t.Helper()
        e := &fakeH3Edge{mode: "echo"}

        uc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
        if err != nil {
                t.Fatalf("udp listen: %v", err)
        }
        udp := uc.(*net.UDPConn)
        srvTLS := &tls.Config{
                Certificates: []tls.Certificate{newSelfSignedCert(t)},
                NextProtos:   []string{"h3"},
        }
        ln, err := quic.Listen(udp, srvTLS, &quic.Config{MaxIncomingStreams: h3MaxStreams})
        if err != nil {
                t.Fatalf("quic listen: %v", err)
        }
        t.Cleanup(func() { _ = ln.Close() })
        e.ln = ln
        go e.serve()
        return e
}

func (e *fakeH3Edge) serve() {
        ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
        defer cancel()
        for {
                conn, err := e.ln.Accept(ctx)
                if err != nil {
                        return
                }
                go e.handleConn(conn)
        }
}

func (e *fakeH3Edge) handleConn(conn *quic.Conn) {
        e.mu.Lock()
        e.connAccepts++
        kill := e.mode == "kill"
        e.mu.Unlock()
        if kill {
                _ = conn.CloseWithError(quic.ApplicationErrorCode(0), "kill fixture")
                return
        }
        ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
        defer cancel()
        if _, err := acceptControlStreams(ctx, conn); err != nil {
                _ = conn.CloseWithError(quic.ApplicationErrorCode(0x01), "control failed")
                return
        }
        for {
                stream, err := conn.AcceptStream(ctx)
                if err != nil {
                        return
                }
                if !e.handleConnect(conn, stream) {
                        return
                }
        }
}

func (e *fakeH3Edge) handleConnect(conn *quic.Conn, stream *quic.Stream) bool {
        e.mu.Lock()
        e.connects++
        mode, fixedStatus, expectToken, tracePayload := e.mode, e.fixedStatus, e.expectToken, e.tracePayload
        e.mu.Unlock()

        fr := newH3Framer(stream)
        _, payload, err := fr.ReadKnownFrame(map[uint64]bool{h3FrameHeaders: true})
        if err != nil {
                return false
        }
        fields, derr := DecodeFieldSection(payload)
        if derr != nil || len(fields) < 2 {
                _ = conn.CloseWithError(quic.ApplicationErrorCode(0x02), "bad CONNECT headers")
                return false
        }
        methodOK := false
        for _, kv := range fields {
                switch kv[0] {
                case ":method":
                        methodOK = kv[1] == "CONNECT"
                case ":authority":
                        e.mu.Lock()
                        e.lastAuthority = kv[1]
                        e.mu.Unlock()
                case "proxy-authorization":
                        e.mu.Lock()
                        e.lastAuth = kv[1]
                        e.mu.Unlock()
                }
        }
        if !methodOK {
                _ = conn.CloseWithError(quic.ApplicationErrorCode(0x02), "not a CONNECT")
                return false
        }

        status := 200
        if expectToken != "" && e.lastAuthValue() != "Bearer "+expectToken {
                status = http.StatusProxyAuthRequired
        } else if fixedStatus > 0 {
                status = fixedStatus
        }
        if mode == "hang" && status == 200 {
                // Hang BEFORE any response byte: the client open budget must fire.
                <-conn.Context().Done()
                return false
        }
        if status != 200 {
                wr := responseWriter{}
                wr.literal(":status", strconv.Itoa(status))
                if _, werr := stream.Write(appendH3Headers(nil, wr.b)); werr != nil {
                        return false
                }
                _ = stream.Close()
                return true
        }

        wr := responseWriter{}
        wr.indexedStatus200()
        if _, werr := stream.Write(appendH3Headers(nil, wr.b)); werr != nil {
                return false
        }

        switch mode {
        case "silent":
                _ = stream.Close() // headers only; FIN => client reads EOF
                return true
        case "teardown":
                dataFr := newH3Framer(stream)
                typ, data, derr := dataFr.ReadKnownFrame(map[uint64]bool{h3FrameData: true})
                if derr != nil || typ != h3FrameData {
                        return false
                }
                if _, werr := stream.Write(appendH3Frame(nil, h3FrameData, data)); werr != nil {
                        return false
                }
                time.Sleep(50 * time.Millisecond)
                _ = conn.CloseWithError(quic.ApplicationErrorCode(0x03), "teardown mid-stream")
                return false
        default: // echo DATA frames until the client goes away
                dataFr := newH3Framer(stream)
                for {
                        typ, data, derr := dataFr.ReadKnownFrame(map[uint64]bool{h3FrameData: true})
                        if derr != nil {
                                return true
                        }
                        if typ != h3FrameData {
                                continue
                        }
                        if tracePayload != "" && strings.HasPrefix(e.lastAuthorityValue(), exitProbeHost+":") {
                                if _, werr := stream.Write(appendH3Frame(nil, h3FrameData, []byte(tracePayload))); werr != nil {
                                        return false
                                }
                                continue
                        }
                        if _, werr := stream.Write(appendH3Frame(nil, h3FrameData, data)); werr != nil {
                                return false
                        }
                }
        }
}

func (e *fakeH3Edge) lastAuthValue() string {
        e.mu.Lock()
        defer e.mu.Unlock()
        return e.lastAuth
}

func (e *fakeH3Edge) lastAuthorityValue() string {
        e.mu.Lock()
        defer e.mu.Unlock()
        return e.lastAuthority
}

func (e *fakeH3Edge) addr() (string, int) {
        host, portStr, _ := net.SplitHostPort(e.ln.Addr().String())
        port, _ := strconv.Atoi(portStr)
        return host, port
}

func (e *fakeH3Edge) setBehavior(mode string, fixedStatus int, expectToken string) {
        e.mu.Lock()
        defer e.mu.Unlock()
        e.mode = mode
        e.fixedStatus = fixedStatus
        e.expectToken = expectToken
}

func (e *fakeH3Edge) counters() (connects int, accepts int, auth string) {
        e.mu.Lock()
        defer e.mu.Unlock()
        return e.connects, e.connAccepts, e.lastAuth
}

// responseWriter assembles a minimal QPACK response field section
// (embedding the qpack encoder primitives).
type responseWriter struct{ qpackWriter }

func (w *responseWriter) indexedStatus200() {
        w.initPrefix()
        w.b = append(w.b, 0xC0|qpackIdxStatus200) // indexed static :status 200 -> 0xD9
}

func (w *responseWriter) literal(name, value string) {
        w.initPrefix()
        w.encodeLiteralNameLine(name, value)
}

func (w *responseWriter) initPrefix() {
        if len(w.b) == 0 {
                w.b = appendQPACKInt(w.b, 0x00, 8, 0) // Required Insert Count = 0
                w.b = appendQPACKInt(w.b, 0x00, 7, 0) // Base = 0
        }
}

func dialH3Test(t *testing.T, e *fakeH3Edge, token string) *H3Tunnel {
        t.Helper()
        host, port := e.addr()
        s, err := DialH3(context.Background(), testTunnelConfig(host, port, token))
        if err != nil {
                t.Fatalf("DialH3: %v", err)
        }
        t.Cleanup(func() { _ = s.Close() })
        return s
}

// fakeResolver maps every name onto one IP (review F2 stand: the production
// server list serves hostnames — atn1.m1.fastly-masque.net — while the fake
// edge listens on loopback).
type fakeResolver struct{ ip net.IP }

func (r fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
        return []net.IPAddr{{IP: r.ip}}, nil
}

// TestH3DialsByHostname pins review F2: a HOSTNAME edge is dialable — the
// name resolves to the carrier IP, SNI stays the name, the session carries
// CONNECT relays.
func TestH3DialsByHostname(t *testing.T) {
        e := newFakeH3Edge(t)
        _, port := e.addr()

        cfg := testTunnelConfig("atn1.m1.fastly-masque.net", port, "jwt-1")
        cfg.Resolver = fakeResolver{ip: net.ParseIP("127.0.0.1")}
        s, err := DialH3(context.Background(), cfg)
        if err != nil {
                t.Fatalf("DialH3 by hostname: %v", err)
        }
        t.Cleanup(func() { _ = s.Close() })

        conn, err := s.OpenTunnel(context.Background(), "target.example:443")
        if err != nil {
                t.Fatalf("OpenTunnel: %v", err)
        }
        defer conn.Close()
        payload := []byte("hello over a named edge")
        if _, err := conn.Write(payload); err != nil {
                t.Fatalf("write: %v", err)
        }
        got := make([]byte, len(payload))
        if _, err := io.ReadFull(conn, got); err != nil {
                t.Fatalf("read: %v", err)
        }
        if string(got) != string(payload) {
                t.Fatal("echo mismatch")
        }
}

// TestH3UnresolvableHostFailsFast pins the F2 error surface: a name that
// resolves to nothing fails the dial inside the handshake budget (never a
// dial into UDPAddr{IP:nil}).
func TestH3UnresolvableHostFailsFast(t *testing.T) {
        e := newFakeH3Edge(t)
        _, port := e.addr()

        cfg := testTunnelConfig("dead.m1.fastly-masque.net", port, "jwt-1")
        cfg.Resolver = fakeResolver{ip: nil} // resolver returns an empty answer
        cfg.HandshakeBudget = 2 * time.Second
        if _, err := DialH3(context.Background(), cfg); err == nil {
                t.Fatal("unresolvable hostname must fail the dial")
        }
}
