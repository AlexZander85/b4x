package health

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/reserve"
)

type fakeCarrier struct {
	addr netip.AddrPort
	kind reserve.Kind
	fail bool
}

func (f *fakeCarrier) Kind() reserve.Kind { return f.kind }
func (f *fakeCarrier) SupportsUDP() bool  { return false }
func (f *fakeCarrier) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, reserve.ErrCarrierNoUDP
}
func (f *fakeCarrier) DialStream(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	if f.fail {
		return nil, errors.New("stand: no session")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", f.addr.String())
}

func TestMeasureThroughCarrier(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 2048))
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))

	fc := &fakeCarrier{addr: ap, kind: reserve.KindFxvpn}
	p := New(Config{
		Target:             ap,
		ServerName:         "example.test",
		Path:               "/",
		Timeout:            3 * time.Second,
		Samples:            2,
		MaxBytes:           1024,
		InsecureSkipVerify: true,
	})
	m := p.Measure(context.Background(), fc)

	if !m.Available {
		t.Fatalf("expected available, got %+v (err=%s)", m, m.Error)
	}
	if m.Kind != string(reserve.KindFxvpn) {
		t.Fatalf("kind=%q", m.Kind)
	}
	if m.Probes != 2 || m.Failures != 0 {
		t.Fatalf("probes=%d failures=%d", m.Probes, m.Failures)
	}
	if m.Bytes <= 0 || m.TTFBms < 0 || m.RTTms < 0 {
		t.Fatalf("measurement empty: %+v", m)
	}
	if m.Score <= 0 || m.Verdict == VerdictUnavailable {
		t.Fatalf("score/verdict wrong: %+v", m)
	}
}

func TestMeasureUnavailableOnDialFailure(t *testing.T) {
	fc := &fakeCarrier{fail: true, kind: reserve.KindOpera}
	p := New(Config{
		Target:     netip.MustParseAddrPort("127.0.0.1:1"),
		ServerName: "example.test",
		Samples:    2,
		Timeout:    time.Second,
	})
	m := p.Measure(context.Background(), fc)

	if m.Available {
		t.Fatalf("expected unavailable: %+v", m)
	}
	if m.Failures != 2 || m.LossPct != 100 {
		t.Fatalf("loss bookkeeping wrong: %+v", m)
	}
	if m.Verdict != VerdictUnavailable {
		t.Fatalf("verdict=%q", m.Verdict)
	}
	if m.Error == "" {
		t.Fatal("error must be surfaced")
	}
}

func TestCachePutGetSnapshot(t *testing.T) {
	c := NewCache()
	if _, ok := c.Get("warp"); ok {
		t.Fatal("empty cache must miss")
	}
	c.Put(Metrics{Kind: "warp", Score: 42})
	if m, ok := c.Get("warp"); !ok || m.Score != 42 {
		t.Fatalf("get=%+v ok=%t", m, ok)
	}
	if snap := c.Snapshot(); len(snap) != 1 {
		t.Fatalf("snapshot=%+v", snap)
	}
}
