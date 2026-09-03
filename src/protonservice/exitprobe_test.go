// Exit-verification tests (review §6): a fake edge with a known country
// drives the P1 paths — trace parsing, the mismatch verdict (event +
// strike + retirement), the verified happy path, and the auto-mode skip.
package protonservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/transport/proton"
)

// newTraceEdge serves the Cloudflare trace shape with the given country
// and ip over TLS (the fake exit edge of review §6).
func newTraceEdge(t *testing.T, country, ip string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(exitProbePath, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ip=%s\nloc=%s\nhttp=/http/1.1\n", ip, country)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// testProbeDialer sends every probe dial to the fake edge regardless of
// the requested address and returns the TLS base that trusts the edge
// certificate (probeExitTLS clones it; the cert SAN is example.com).
func testProbeDialer(t *testing.T, srv *httptest.Server) (exitDialFunc, *tls.Config) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", strings.TrimPrefix(srv.URL, "https://"))
	}
	return dial, &tls.Config{RootCAs: pool, ServerName: "example.com"}
}

func newExitTestRuntime(t *testing.T, loc config.ProtonLocation) *Runtime {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.System.Proton = config.ProtonConfig{
		Enabled:      true,
		IdentityPath: filepath.Join(dir, "identity.json"),
		Location:     loc,
	}
	rt, err := Build(cfg, Options{Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	rt.client.Pins = mustPinsMemory(t)
	return rt
}

func exitProbeNode() proton.Node {
	return proton.Node{
		Name: "NL-FREE#1", Country: "NL", City: "Amsterdam",
		EntryIP: "203.0.113.10", PeerPubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
}

func exitProbeProfile() proton.ProtonProfile {
	return proton.ProtonProfile{
		Node:      exitProbeNode(),
		Port:      443,
		ProfileID: "proton-quic",
	}
}

// TestProbeExitParsesTrace pins the wire shape of the probe: GET the trace
// path, read ip=/loc=.
func TestProbeExitParsesTrace(t *testing.T) {
	edge := newTraceEdge(t, "NL", "203.0.113.7")
	dial, tlsBase := testProbeDialer(t, edge)
	info, err := probeExitTLS(context.Background(), dial, tlsBase)
	if err != nil {
		t.Fatal(err)
	}
	if info.Country != "NL" || info.IP != "203.0.113.7" {
		t.Fatalf("unexpected exit info %+v", info)
	}
}

// TestRunExitProbeMismatchStrikesAndRetires is the review §6 scenario: a
// fake edge with a known country that differs from the requested location
// must (a) fill r.exit, (b) emit proton_exit_mismatch with the class,
// (c) strike the node into cooldown, (d) retire the session (state ->
// backoff), (e) clear the probe latch.
func TestRunExitProbeMismatchStrikesAndRetires(t *testing.T) {
	rt := newExitTestRuntime(t, config.ProtonLocation{Mode: "country", Country: "US"})
	edge := newTraceEdge(t, "NL", "203.0.113.7")
	dial, tlsBase := testProbeDialer(t, edge)
	rt.opts.ExitProbeTLS = tlsBase

	node := exitProbeNode()
	prof := exitProbeProfile()
	prof.Node = node

	rt.runExitProbe(node, prof, nil, dial)

	if !rt.exit.OK || rt.exit.Country != "NL" || rt.exit.IP != "203.0.113.7" {
		t.Fatalf("exit view not filled: %+v", rt.exit)
	}
	rt.mu.Lock()
	probing, last, state := rt.exitProbing, rt.lastFailure, rt.state
	rt.mu.Unlock()
	if probing {
		t.Fatal("exitProbing not cleared")
	}
	if last != proton.ClassExitMismatch {
		t.Fatalf("lastFailure = %q, want %q", last, proton.ClassExitMismatch)
	}
	if state != StateBackoff {
		t.Fatalf("state = %q, want backoff after mismatch", state)
	}
	if !rt.strikes.Cooling(prof.AddrPort(), time.Now()) {
		t.Fatal("node was not struck into cooldown on verified mismatch")
	}
	found := false
	for _, ev := range rt.Status().Events {
		if ev.Name == proton.EventExitMismatch && ev.Class == proton.ClassExitMismatch {
			found = true
		}
	}
	if !found {
		t.Fatalf("proton_exit_mismatch event missing in %+v", rt.Status().Events)
	}
}

// TestRunExitProbeVerifiedCountry: edge country == requested -> verified,
// no strike, no mismatch event.
func TestRunExitProbeVerifiedCountry(t *testing.T) {
	rt := newExitTestRuntime(t, config.ProtonLocation{Mode: "country", Country: "NL"})
	edge := newTraceEdge(t, "NL", "203.0.113.7")
	dial, tlsBase := testProbeDialer(t, edge)
	rt.opts.ExitProbeTLS = tlsBase

	node := exitProbeNode()
	prof := exitProbeProfile()
	prof.Node = node

	rt.runExitProbe(node, prof, nil, dial)

	if !rt.exit.OK || rt.exit.Country != "NL" {
		t.Fatalf("exit view: %+v", rt.exit)
	}
	if rt.strikes.Cooling(prof.AddrPort(), time.Now()) {
		t.Fatal("a verified exit must not strike the node")
	}
	found := false
	for _, ev := range rt.Status().Events {
		if ev.Name == "proton_exit_verified" {
			found = true
		}
	}
	if !found {
		t.Fatalf("proton_exit_verified event missing in %+v", rt.Status().Events)
	}
}

// TestRunExitProbeAutoModeSkips: mode=auto has no expected country — any
// exit verifies (no mismatch verdict, exit view still filled).
func TestRunExitProbeAutoModeSkips(t *testing.T) {
	rt := newExitTestRuntime(t, config.ProtonLocation{Mode: "auto"})
	edge := newTraceEdge(t, "US", "198.51.100.9")
	dial, tlsBase := testProbeDialer(t, edge)
	rt.opts.ExitProbeTLS = tlsBase

	node := exitProbeNode()
	prof := exitProbeProfile()
	prof.Node = node

	rt.runExitProbe(node, prof, nil, dial)

	if !rt.exit.OK || rt.exit.Country != "US" {
		t.Fatalf("exit view: %+v", rt.exit)
	}
	for _, ev := range rt.Status().Events {
		if ev.Name == proton.EventExitMismatch {
			t.Fatalf("auto mode must not emit mismatch: %+v", ev)
		}
	}
}

// TestDesiredExitCountry pins the want-country resolution matrix: country
// mode -> configured code (upper-cased); host mode -> the node's declared
// country; auto -> "" (nothing to compare).
func TestDesiredExitCountry(t *testing.T) {
	rt := newExitTestRuntime(t, config.ProtonLocation{Mode: "country", Country: "nl"})
	rt.mu.Lock()
	got := rt.desiredExitCountryLocked(exitProbeNode())
	rt.mu.Unlock()
	if got != "NL" {
		t.Fatalf("country mode: got %q want NL", got)
	}
	rt.mu.Lock()
	rt.location = config.ProtonLocation{Mode: "host"}
	got = rt.desiredExitCountryLocked(exitProbeNode())
	rt.mu.Unlock()
	if got != "NL" {
		t.Fatalf("host mode: got %q want the node country NL", got)
	}
	rt.mu.Lock()
	rt.location = config.ProtonLocation{Mode: "auto"}
	got = rt.desiredExitCountryLocked(exitProbeNode())
	rt.mu.Unlock()
	if got != "" {
		t.Fatalf("auto mode: got %q want empty", got)
	}
}
