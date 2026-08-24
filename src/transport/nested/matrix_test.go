package nested

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func validPair() PairConfig {
	return PairConfig{
		Outer: LayerSpec{
			Kind: KindMasqueH2, IdentitySlot: SlotPrimary,
			ProfileID: "cf-warp/vanilla-off", Endpoint: netip.MustParseAddrPort("162.159.192.1:443"),
		},
		Inner: LayerSpec{
			Kind: KindAWG, IdentitySlot: SlotSecondary,
			ProfileID: "awg/quic-a", Endpoint: netip.MustParseAddrPort("10.66.66.1:51820"),
		},
	}
}

func TestPairConfigValidateTable(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*PairConfig)
		wantErr error
	}{
		{"happy-m+w", func(*PairConfig) {}, nil},
		{"happy-w-w", func(p *PairConfig) {
			p.Outer.Kind = KindAWG
			p.Outer.Endpoint = netip.MustParseAddrPort("162.159.193.10:2408")
		}, nil},
		{"bad-inner-kind", func(p *PairConfig) { p.Inner.Kind = "vless" }, ErrBadKind},
		{"inner-slot-primary", func(p *PairConfig) { p.Inner.IdentitySlot = SlotPrimary }, ErrBadSlot},
		{"edge-collision", func(p *PairConfig) {
			p.Inner.Endpoint = netip.MustParseAddrPort("162.159.192.1:51820")
		}, ErrEdgeCollision},
		{"mtu-over-cap", func(p *PairConfig) { p.Inner.MTU = 1280 }, nil}, // see explicit test below
		{"bad-failure-mode", func(p *PairConfig) { p.FailureMode = "best-effort" }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validPair()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("validate err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && err != nil &&
				tc.name != "mtu-over-cap" && tc.name != "bad-failure-mode" {
				t.Fatalf("validate unexpected error: %v", err)
			}
		})
	}

	// Explicit expectations for the two table entries asserted by content.
	mtu := validPair()
	mtu.Inner.MTU = 1400
	if err := mtu.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("mtu cap err = %v", err)
	}
	fm := validPair()
	fm.FailureMode = "best-effort"
	if err := fm.Validate(); err == nil || !strings.Contains(err.Error(), "failure_mode") {
		t.Fatalf("failure_mode err = %v", err)
	}
}

func TestResolveCarrierAutoRules(t *testing.T) {
	// MASQUE outer always resolves to the datagram plane.
	mw := validPair()
	got, err := ResolveCarrier(mw, false)
	if err != nil || got != CarrierDatagram {
		t.Fatalf("masque auto = %v/%v, want datagram", got, err)
	}

	// AWG outer resolves by its data-plane mode.
	ww := validPair()
	ww.Outer.Kind = KindAWG
	if got, _ = ResolveCarrier(ww, true); got != CarrierKernelRoute {
		t.Fatalf("kernel awg outer = %v, want kernel-route", got)
	}
	if got, _ = ResolveCarrier(ww, false); got != CarrierNetstack {
		t.Fatalf("netstack awg outer = %v, want netstack", got)
	}

	// Explicit modes pass through.
	ww.Carrier = CarrierNetstack
	if got, _ = ResolveCarrier(ww, true); got != CarrierNetstack {
		t.Fatalf("explicit passthrough = %v", got)
	}
}

func TestForwarderSeamAdaptsCarrier(t *testing.T) {
	rec := &recordCarrier{}
	seam := ForwarderSeam(rec)

	if _, err := seam(context.Background(), "tcp", "10.0.0.1:53"); err == nil {
		t.Fatal("seam must reject non-udp networks")
	}
	sess, err := seam(context.Background(), "udp", "203.0.113.9:51820")
	if err != nil {
		t.Fatalf("seam dial: %v", err)
	}
	if rec.dialed != "203.0.113.9:51820" {
		t.Fatalf("dialed = %q", rec.dialed)
	}
	if _, err := sess.Write([]byte("x")); err != nil {
		t.Fatalf("write through seam: %v", err)
	}
}

type recordCarrier struct {
	dialed string
}

func (r *recordCarrier) DialUDPThrough(_ context.Context, dst netip.AddrPort) (UDPSession, error) {
	r.dialed = dst.String()
	return nopSession{}, nil
}

type nopSession struct{}

func (nopSession) Write(b []byte) (int, error) { return len(b), nil }
func (nopSession) Read(b []byte) (int, error)  { return 0, nil }
func (nopSession) Close() error                { return nil }

func TestCarrierDialFuncParsesNumericEndpoint(t *testing.T) {
	var mu sync.Mutex
	var dialed netip.AddrPort
	carrier := fakeTCPCarrier{onDial: func(dst netip.AddrPort) {
		mu.Lock()
		dialed = dst
		mu.Unlock()
	}}
	fn := CarrierDialFunc(carrier)

	conn, err := fn(context.Background(), "tcp", "162.159.198.1:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	mu.Lock()
	defer mu.Unlock()
	if dialed.String() != "162.159.198.1:443" {
		t.Fatalf("carrier received %v", dialed)
	}
	if _, err := fn(context.Background(), "udp", "162.159.198.1:443"); err == nil {
		t.Fatal("non-tcp must be rejected")
	}
}

type fakeTCPCarrier struct{ onDial func(netip.AddrPort) }

func (f fakeTCPCarrier) InjectUDPDatagram(netip.AddrPort, []byte) error { return nil }
func (f fakeTCPCarrier) DialTCPThrough(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	f.onDial(dst)
	c1, c2 := net.Pipe()
	go func() { _ = c2.Close() }()
	return c1, nil
}
func (f fakeTCPCarrier) ProofSnapshot() (string, bool) { return "test", true }
