package opera

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// fakeH2Edge is a REAL HTTP/2 server (http2.ConfigureServer) behind a TLS
// front that counts handshakes; its CONNECT handler echoes bytes back.
type fakeH2Edge struct {
	addr       string
	handshakes atomic.Int32
	srv        *http.Server
}

func newFakeH2Edge(t *testing.T, ca *testCA, cn string) *fakeH2Edge {
	t.Helper()
	cert := ca.issueLeaf(t, cn)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("edge: %s %s", r.Method, r.Host)
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		t.Log("edge: 200 flushed, copying")
		// Every echo write MUST flush: h2 response buffering would
		// otherwise withhold the DATA frames (fxvpn relayPipe lesson).
		n, err := io.Copy(flushWriter{w}, r.Body)
		t.Logf("edge: copied %d bytes err=%v", n, err)
	})}
	h2 := &http2.Server{}
	http2.ConfigureServer(srv, h2)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	e := &fakeH2Edge{addr: ln.Addr().String(), srv: srv}
	wrapped := &countingListener{Listener: ln, count: &e.handshakes}
	go func() { _ = srv.Serve(tls.NewListener(wrapped, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return e
}

type countingListener struct {
	net.Listener
	count *atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.count.Add(1)
	}
	return c, err
}

// flushWriter flushes after every write (h2 response buffering would
// otherwise withhold the relayed bytes and deadlock the tunnel).
type flushWriter struct{ w io.Writer }

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if f2, ok := f.w.(http.Flusher); ok {
		f2.Flush()
	}
	return n, err
}

// TestH2ConnectMultiplex (review §7.7 OP-M2): N tunnel dials ride ONE TLS
// handshake (the handshake-burst signature dies) and every stream relays
// bytes end-to-end.
func TestH2ConnectMultiplex(t *testing.T) {
	ca := newTestCA(t, "opera-h2-ca")
	edge := newFakeH2Edge(t, ca, "eu0.sec-tunnel.com")

	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          func() (string, error) { return BasicAuthHeader("l", "p"), nil },
		RootPool:      ca.pool,
		Masquerade:    DefaultMasquerade(), // h2-first ALPN
		USessionCache: utls.NewLRUClientSessionCache(4),
		h2:            &h2Pool{},
	}

	dialEcho := func(payload string) string {
		conn, err := d.DialContext(context.Background(), "tcp", "www.gstatic.com:80")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		return string(buf)
	}

	for i := 0; i < 4; i++ {
		if got := dialEcho("ping-multiplexed"); got != "ping-multiplexed" {
			t.Fatalf("stream %d echoed %q", i, got)
		}
	}
	if n := edge.handshakes.Load(); n != 1 {
		t.Fatalf("TLS handshakes = %d, want 1 (multiplex broken)", n)
	}
}

// TestH2FallbackWhenEngineAbsent: without the h2 pool the ALPN offer is
// trimmed so the node CANNOT negotiate h2 — the tunnel must keep working
// over the 1.1 CONNECT engine.
func TestH2FallbackWhenEngineAbsent(t *testing.T) {
	ca := newTestCA(t, "opera-h2-ca")
	edge := newFakeH2Edge(t, ca, "eu0.sec-tunnel.com") // advertises h2 ONLY

	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          func() (string, error) { return BasicAuthHeader("l", "p"), nil },
		RootPool:      ca.pool,
		Masquerade:    DefaultMasquerade(), // would offer h2...
		USessionCache: utls.NewLRUClientSessionCache(4),
		h2:            nil, // ...but the engine is absent
	}
	conn, err := d.DialContext(context.Background(), "tcp", "www.gstatic.com:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// The meaningful assertion: WITHOUT the h2 engine the wire never
	// offers h2 (ALPN trimmed), so the node can never negotiate it into a
	// 1.1-speaking engine. The h2-only edge falls back to serving 1.1 on
	// this connection (net/http keeps both handlers), which is fine.
	if proto := negotiatedProtocol(conn); proto == "h2" {
		t.Fatalf("negotiated %q without an h2 engine — ALPN trim broken", proto)
	}
	if got := edge.handshakes.Load(); got < 1 {
		t.Fatal("handshake never reached the edge")
	}
}

// TestFilterALPN: order kept, drop targeted.
func TestFilterALPN(t *testing.T) {
	got := filterALPN([]string{"h2", "http/1.1"}, "h2")
	if len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("filterALPN = %v", got)
	}
	if got := filterALPN(nil, "h2"); len(got) != 0 {
		t.Fatalf("filterALPN(nil) = %v, want empty", got)
	}
}
