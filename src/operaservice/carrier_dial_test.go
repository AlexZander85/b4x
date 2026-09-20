package operaservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/daniellavrushin/b4/reserve"
)

var errBaseTest = errors.New("fake base dial")

type fakeBaseCarrier struct {
	kind   reserve.Kind
	stream int
	last   string
}

func (f *fakeBaseCarrier) Kind() reserve.Kind { return f.kind }
func (f *fakeBaseCarrier) SupportsUDP() bool  { return false }
func (f *fakeBaseCarrier) DialStream(_ context.Context, addr netip.AddrPort) (net.Conn, error) {
	f.stream++
	f.last = addr.String()
	return nil, errBaseTest
}
func (f *fakeBaseCarrier) DialUDP(_ context.Context, _ netip.AddrPort) (net.Conn, error) {
	return nil, reserve.ErrCarrierNoUDP
}

type fakeHostCarrier struct {
	fakeBaseCarrier
	hostHit int
	conn    net.Conn
}

func (f *fakeHostCarrier) DialStreamHost(_ context.Context, host string, port uint16) (net.Conn, error) {
	f.hostHit++
	f.last = net.JoinHostPort(host, "443")
	if f.conn != nil {
		return f.conn, nil
	}
	return nil, errBaseTest
}

// TestBaseCarrierDialFailsClosedWithoutBase: no base transport registered =>
// the dial errors instead of silently going direct.
func TestBaseCarrierDialFailsClosedWithoutBase(t *testing.T) {
	reserve.Reset()
	defer reserve.Reset()
	if _, err := BaseCarrierDial()(context.Background(), "tcp", "1.2.3.4:443"); err == nil {
		t.Fatal("dial without a base carrier must fail closed")
	}
}

// TestBaseCarrierDialUsesHostSeam: the hostname-capable base carrier gets the
// domain (in-tunnel DNS) and its conn is returned.
func TestBaseCarrierDialUsesHostSeam(t *testing.T) {
	reserve.Reset()
	defer reserve.Reset()
	client, server := net.Pipe()
	defer server.Close()
	hc := &fakeHostCarrier{conn: client}
	hc.kind = reserve.KindMasque
	reserve.Register(hc)

	conn, err := BaseCarrierDial()(context.Background(), "tcp", "api2.sec-tunnel.com:443")
	if err != nil {
		t.Fatalf("carrier dial: %v", err)
	}
	_ = conn.Close()
	if hc.hostHit != 1 || hc.stream != 0 || hc.last != "api2.sec-tunnel.com:443" {
		t.Fatalf("host seam not used: hostHit=%d stream=%d last=%q", hc.hostHit, hc.stream, hc.last)
	}
}

// TestBaseCarrierDialPicksHighestPriority: with two base carriers the
// higher-priority kind (warp 60 > masque 50) is used, and an IP literal goes
// through DialStream.
func TestBaseCarrierDialPicksHighestPriority(t *testing.T) {
	reserve.Reset()
	defer reserve.Reset()
	masque := &fakeHostCarrier{}
	masque.kind = reserve.KindMasque
	warp := &fakeBaseCarrier{kind: reserve.KindWarp}
	reserve.Register(masque)
	reserve.Register(warp)

	if _, err := BaseCarrierDial()(context.Background(), "tcp", "9.9.9.9:443"); !errors.Is(err, errBaseTest) {
		t.Fatalf("dial err = %v, want the carrier error", err)
	}
	if warp.stream != 1 || warp.last != "9.9.9.9:443" {
		t.Fatalf("priority pick wrong: warp.stream=%d last=%q (masque.hostHit=%d)", warp.stream, warp.last, masque.hostHit)
	}
	if masque.hostHit != 0 {
		t.Fatalf("lower-priority carrier must not be used (hostHit=%d)", masque.hostHit)
	}
}
