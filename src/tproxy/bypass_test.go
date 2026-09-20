package tproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/socks5"
)

// fakeBypassCarrier lets the anti-loop test observe whether the tunnel was
// used; when bypass is true it declares every domain as its own
// infrastructure (like opera and *.sec-tunnel.com).
type fakeBypassCarrier struct {
	bypass bool
	calls  int
}

var errFakeDial = errors.New("fake carrier dial")

func (f *fakeBypassCarrier) Kind() reserve.Kind { return reserve.KindOpera }
func (f *fakeBypassCarrier) DialStream(_ context.Context, _ netip.AddrPort) (net.Conn, error) {
	f.calls++
	return nil, errFakeDial
}
func (f *fakeBypassCarrier) SupportsUDP() bool { return false }
func (f *fakeBypassCarrier) DialUDP(_ context.Context, _ netip.AddrPort) (net.Conn, error) {
	return nil, reserve.ErrCarrierNoUDP
}
func (f *fakeBypassCarrier) BypassDomain(_ string) bool { return f.bypass }

// TestDialTunnelTCPBypassesCarrierOwnDomains: a flow whose domain the carrier
// declares as its own infrastructure is delivered DIRECT (anti-loop), never
// through the carrier; other domains still ride the carrier.
func TestDialTunnelTCPBypassesCarrierOwnDomains(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	ip := net.ParseIP("127.0.0.1")

	bypass := &fakeBypassCarrier{bypass: true}
	l := &Listener{SetName: "s", Tunnel: bypass, TunnelKind: "opera", Upstream: socks5.ClientConfig{}}
	conn, derr := l.dialTunnelTCP(context.Background(), ip, port, "api2.sec-tunnel.com")
	if derr != nil {
		t.Fatalf("bypassed dial: %v", derr)
	}
	_ = conn.Close()
	if bypass.calls != 0 {
		t.Fatalf("bypassed flow must not use the carrier (calls=%d)", bypass.calls)
	}

	nonBypass := &fakeBypassCarrier{bypass: false}
	l2 := &Listener{SetName: "s", Tunnel: nonBypass, TunnelKind: "opera", Upstream: socks5.ClientConfig{}}
	if _, derr := l2.dialTunnelTCP(context.Background(), ip, port, "example.com"); !errors.Is(derr, errFakeDial) {
		t.Fatalf("non-bypassed dial err = %v, want the carrier error", derr)
	}
	if nonBypass.calls != 1 {
		t.Fatalf("non-bypassed flow must ride the carrier (calls=%d)", nonBypass.calls)
	}
}
