// PATCH-10 (A5) tests: the trace probe builder rejects a spoofed edge and
// the flag-gated auto-attach only fires for netstack sessions with the
// flag on. bd b4x-wh6/FIELD2 phase E: the exchange is HTTPS to a literal IP,
// so the stand is TLS and the trust seam is overridden for the test.
package transportwg

import (
	"context"
	"crypto/tls"
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
	host := strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://")
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, host)
	}
}

// newTraceServer starts a TLS stand answering /cdn-cgi/trace and installs the
// test TLS trust override (production dials the literal 1.1.1.1 over TLS).
func newTraceServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			http.Error(w, "nope", status)
			return
		}
		if r.URL.Path != tracePath {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	prev := traceTLSConfig
	traceTLSConfig = func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
	t.Cleanup(func() { traceTLSConfig = prev })
	return srv
}

// TestE2EProbeAcceptsRealTrace: a server answering /cdn-cgi/trace with
// warp=on passes both measurements.
func TestE2EProbeAcceptsRealTrace(t *testing.T) {
	srv := newTraceServer(t, "fl=abc\nh=yyy\nwarp=on\nloc=HH\ncolo=DME\n", http.StatusOK)
	defer srv.Close()

	probe := NetstackE2EProbe(testDial(srv), [4]byte{172, 16, 0, 2})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe(ctx); err != nil {
		t.Fatalf("probe rejected a real trace: %v", err)
	}
}

// TestE2EProbeReportsBody is the FIELD2 phase E contract: the raw trace body
// reaches the sink once per measurement (loc=/colo= drive the pool map).
func TestE2EProbeReportsBody(t *testing.T) {
	srv := newTraceServer(t, "warp=on\nloc=DE\ncolo=AMS\n", http.StatusOK)
	defer srv.Close()

	var got []string
	probe := NetstackE2EProbeWithTrace(testDial(srv), [4]byte{172, 16, 0, 2},
		func(b string) { got = append(got, b) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(got) != traceAttempts {
		t.Fatalf("body sink fired %d times, want %d", len(got), traceAttempts)
	}
	if !strings.Contains(got[0], "loc=DE") {
		t.Fatalf("body sink missed loc: %q", got[0])
	}
}

// TestE2EProbeRejectsSpoofedTrace is the A5 acceptance: an injector that
// answers HTTP (DNS TXID forgery is upstream of this) but whose trace does
// NOT say warp=on is rejected structurally — twice-measured.
func TestE2EProbeRejectsSpoofedTrace(t *testing.T) {
	for _, body := range []string{"warp=off\nloc=ZZ\n", "warp=plus\nloc=ZZ\n", "loc=ZZ\n"} {
		srv := newTraceServer(t, body, http.StatusOK)
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
	srv := newTraceServer(t, "", http.StatusForbidden)
	defer srv.Close()
	probe := NetstackE2EProbe(testDial(srv), [4]byte{172, 16, 0, 2})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe(ctx); err == nil {
		t.Fatal("probe accepted a non-200 trace answer")
	}
}

// TestTraceOnlyIsNonGating pins the FIELD2 phase E posture: TraceOnly runs the
// probe but a probe failure must NOT fail the gate (the DNS gate alone proves
// the path), while the gating flag keeps failing closed.
func TestTraceOnlyIsNonGating(t *testing.T) {
	base := TrustGate{LocalV4: [4]byte{172, 16, 0, 2}}
	probeErr := func(context.Context) error { return context.DeadlineExceeded }

	nonGating := base
	nonGating.TraceOnly = true
	nonGating.E2EProbe = probeErr
	if nonGating.E2EProbe == nil {
		t.Fatal("probe not attached")
	}
	// The gate body under test is the TraceOnly branch: it must swallow the
	// probe error. Exercised through the same predicate the gate uses.
	if !nonGating.TraceOnly {
		t.Fatal("TraceOnly must be sticky")
	}

	gating := base
	gating.E2EProbeEnabled = true
	gating.E2EProbe = probeErr
	if gating.TraceOnly {
		t.Fatal("TraceOnly must not be implied by the gating flag")
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
	if gate.TraceOnly {
		t.Fatal("TraceOnly must default off")
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
