package vless

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

const defaultProbeTestTimeout = 3 * time.Second

func TestParseTrace(t *testing.T) {
	body := "fl=abc\nip=1.2.3.4\nts=1\nloc=DE\ncolo=FRA\nwarp=off\n"
	loc, colo := ParseTrace(body)
	if loc != "DE" || colo != "FRA" {
		t.Fatalf("ParseTrace = %q/%q want DE/FRA", loc, colo)
	}
	if l, c := ParseTrace("garbage\nno-equals\n"); l != "" || c != "" {
		t.Fatalf("garbage trace = %q/%q want empty", l, c)
	}
}

func TestProbeOverStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("loc=NL\ncolo=AMS\n"))
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	prober := &Prober{
		Stream: func(ctx context.Context, n Node, _ netip.AddrPort) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
		TraceURL: srv.URL + "/cdn-cgi/trace",
		Timeout:  defaultProbeTestTimeout,
	}
	res := prober.Probe(context.Background(), Node{UUID: "u", Host: "h.example.org", Port: 443, Security: SecurityTLS, SNI: "www.microsoft.com", Transport: TransportTCP})
	if !res.OK {
		t.Fatalf("probe failed: %+v", res)
	}
	if res.Loc != "NL" || res.Colo != "AMS" {
		t.Fatalf("loc/colo = %q/%q want NL/AMS", res.Loc, res.Colo)
	}
}

func TestProbeStreamError(t *testing.T) {
	prober := &Prober{
		Stream: func(context.Context, Node, netip.AddrPort) (net.Conn, error) {
			return nil, net.UnknownNetworkError("blocked")
		},
		TraceURL: "https://1.1.1.1/cdn-cgi/trace",
		Timeout:  defaultProbeTestTimeout,
	}
	res := prober.Probe(context.Background(), Node{Host: "h.example.org", Port: 443})
	if res.OK || res.Err == "" {
		t.Fatalf("expected failure, got %+v", res)
	}
}
