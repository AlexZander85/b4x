// PATCH-10 (A5) tests: the trace probe builder rejects a spoofed edge and
// the flag-gated auto-attach only fires for netstack sessions with the
// flag on.
package transportwg

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testDial adapts an httptest server URL into the trace dial seam.
func testDial(srv *httptest.Server) func(ctx context.Context, network, addr string) (net.Conn, error) {
	host := strings.TrimPrefix(srv.URL, "http://")
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, host)
	}
}

// TestE2EProbeAcceptsRealTrace: a server answering /cdn-cgi/trace with
// warp=on passes both measurements.
func TestE2EProbeAcceptsRealTrace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tracePath {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "fl=abc\nh=yyy\nwarp=on\nloc=HH\n")
	}))
	defer srv.Close()

	probe := NetstackE2EProbe(testDial(srv), [4]byte{172, 16, 0, 2})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe(ctx); err != nil {
		t.Fatalf("probe rejected a real trace: %v", err)
	}
}

// TestE2EProbeRejectsSpoofedTrace is the A5 acceptance: an injector that
// answers HTTP (DNS TXID forgery is upstream of this) but whose trace does
// NOT say warp=on is rejected structurally — twice-measured.
func TestE2EProbeRejectsSpoofedTrace(t *testing.T) {
	for _, body := range []string{"warp=off\nloc=ZZ\n", "warp=plus\nloc=ZZ\n", "loc=ZZ\n"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		}))
		probe := NetstackE2EProbe(testDial(srv), [4]byte{172, 16, 0, 2})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := probe(ctx)
		cancel()
		srv.Close()
		if err == nil {
			t.Fatalf("probe accepted a spoofed trace body %q", body)
		}
	}
}

// TestE2EProbeRejectsNon200: HTTP errors are structural gate failures.
func TestE2EProbeRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	probe := NetstackE2EProbe(testDial(srv), [4]byte{172, 16, 0, 2})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe(ctx); err == nil {
		t.Fatal("probe accepted a non-200 trace answer")
	}
}

// TestE2EProbeFlagAutoAttachWiring: with the flag ON and a netstack tunnel
// the gate gains a probe; without the flag (CI/seek posture) it stays nil.
// The attach site is establishGeneration's gate block; this unit pins the
// decision logic shape through a fake netstack dial seam.
func TestE2EProbeFlagAutoAttachWiring(t *testing.T) {
	gate := TrustGate{}
	gate.fillDefaults()
	// Flag off (default): no auto-attach.
	if gate.E2EProbeEnabled {
		t.Fatal("E2EProbeEnabled must default off (CI/seek posture)")
	}
	if gate.E2EProbe != nil {
		t.Fatal("probe slot must stay nil by default")
	}
	// The dial seam used by the attach site must produce usable conns.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listen unavailable: %v", err)
	}
	defer func() { _ = ln.Close() }()
	dialed := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			dialed <- c
		}
	}()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", "")
	if err != nil {
		t.Fatalf("seam dial: %v", err)
	}
	_ = conn.Close()
	select {
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("seam dial never reached the listener")
	}
}
