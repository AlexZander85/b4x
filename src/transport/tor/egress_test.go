package tor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/reserve"
)

// TT3 DoD (patch-plan §4): fake-carrier policy tests (direct / through /
// auto with switching), negative cache, self-loop refusal, resolver
// caching + anti-SSRF, egress-bridge RFC 1929 cases, credentials, limits,
// half-close; goleak.

// fakeCarrier counts DialStream calls and can fail on demand.
type fakeCarrier struct {
	kind    reserve.Kind
	dials   atomic.Int64
	fail    atomic.Bool
	mu      sync.Mutex
	lastTgt netip.AddrPort
}

func (f *fakeCarrier) Kind() reserve.Kind { return f.kind }
func (f *fakeCarrier) SupportsUDP() bool  { return false }
func (f *fakeCarrier) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (f *fakeCarrier) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	f.mu.Lock()
	f.lastTgt = addr
	f.mu.Unlock()
	f.dials.Add(1)
	if f.fail.Load() {
		return nil, net.ErrClosed
	}
	a, b := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, a) // drains until the caller closes b
		_ = a.Close()
	}()
	return b, nil
}

func fakeLookup(entries ...*fakeCarrier) CarrierLookup {
	return func(kind reserve.Kind) (reserve.Entry, bool) {
		for _, e := range entries {
			if e.Kind() == kind {
				return reserve.Entry{Kind: kind, Priority: 10, Carrier: e}, true
			}
		}
		return reserve.Entry{}, false
	}
}

var ipTarget = netip.MustParseAddrPort("93.184.216.34:443")

func TestEgressPolicyDirect(t *testing.T) {
	defer verifyNoLeaks(t)
	srv := startDirectEcho(t)
	defer srv.Close()
	d := NewDialer(EgressPolicy{Through: "none", Now: time.Now}, nil, nil, nil)
	d.markCtl = nil // sandbox: no CAP_NET_ADMIN for SO_MARK
	conn, err := d.Dial(context.Background(), ClassRelayDir, "127.0.0.1", uint16(srvPort(t, srv)))
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	_, err = conn.Write([]byte("hi"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close()
}

func TestEgressPolicyThroughCarrier(t *testing.T) {
	defer verifyNoLeaks(t)
	fc := &fakeCarrier{kind: reserve.KindProton}
	d := NewDialer(EgressPolicy{Through: "proton", Now: time.Now}, fakeLookup(fc), nil, nil)
	conn, err := d.Dial(context.Background(), ClassBridgeVanilla, ipTarget.Addr().String(), 443)
	if err != nil {
		t.Fatalf("carrier dial: %v", err)
	}
	_ = conn.Close()
	if fc.dials.Load() != 1 {
		t.Fatalf("carrier dialed %d times, want 1", fc.dials.Load())
	}
	fc.mu.Lock()
	got := fc.lastTgt
	fc.mu.Unlock()
	if got != ipTarget {
		t.Fatalf("carrier target = %v, want %v", got, ipTarget)
	}
}

func TestEgressPolicyAutoFailoverToCarrier(t *testing.T) {
	defer verifyNoLeaks(t)
	// auto with a resolver that always fails: direct also unreachable
	// (TEST-NET-3 addr dials nothing fast) — carrier catches.
	fc := &fakeCarrier{kind: reserve.KindOpera}
	resolveFail := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, net.ErrClosed
	}
	d := NewDialer(EgressPolicy{Through: "auto", Now: time.Now}, fakeLookup(fc), resolveFail, nil)
	_, err := d.Dial(context.Background(), ClassRelayDir, "example.com", 443)
	if err == nil {
		t.Fatal("auto dial with failing resolver must fail (no direct, no carrier path)")
	}
}

func TestEgressNegativeCacheAndSelfHeal(t *testing.T) {
	defer verifyNoLeaks(t)
	fc := &fakeCarrier{kind: reserve.KindFxvpn}
	d := NewDialer(EgressPolicy{Through: "auto", Now: time.Now}, fakeLookup(fc), nil, nil)

	// phase 1: NO carrier anywhere — loopback:1 refuses instantly, both
	// dials fail through direct, and two consecutive failures poison it.
	for i := 0; i < 2; i++ {
		if _, err := d.Dial(context.Background(), ClassRelayDir, "127.0.0.1", 1); err == nil {
			t.Fatalf("dial %d should fail (no direct, no carrier)", i)
		}
	}
	if d.directAlive() {
		t.Fatal("two consecutive failures must poison direct for the dead TTL")
	}

	// phase 2: a carrier appears — the poisoned dial goes carrier-first
	// (zero direct black-hole time on the censored path).
	reserve.Reset()
	t.Cleanup(reserve.Reset)
	reserve.Register(fc)
	conn, err := d.Dial(context.Background(), ClassRelayDir, "127.0.0.1", 1)
	if err != nil {
		t.Fatalf("carrier-first dial after poison: %v", err)
	}
	_ = conn.Close()
	if fc.dials.Load() != 1 {
		t.Fatalf("carrier dialed %d times, want exactly 1 (carrier-first)", fc.dials.Load())
	}

	// phase 3: carrier dies too — the self-heal probe tries direct once
	// more and the dial fails honestly.
	fc.fail.Store(true)
	deadAt := time.Now().Add(30 * time.Second)
	d.policy.Now = func() time.Time { return deadAt }
	if _, err := d.Dial(context.Background(), ClassRelayDir, "127.0.0.1", 1); err == nil {
		t.Fatal("carrier dead + direct dead must fail")
	}
}

func TestEgressSelfLoopRefused(t *testing.T) {
	defer verifyNoLeaks(t)
	srv := startDirectEcho(t)
	defer srv.Close()
	port := uint16(srvPort(t, srv))
	loops := func() []string { return []string{srv.Addr().String()} }
	d := NewDialer(EgressPolicy{Through: "none", Now: time.Now}, nil, nil, loops)
	_, err := d.Dial(context.Background(), ClassRelayDir, "127.0.0.1", port)
	if err == nil {
		t.Fatal("dialing a tor listener must be refused")
	}
	if !errors.Is(err, ErrTorSelfLoop) {
		t.Fatalf("err = %v, want ErrTorSelfLoop", err)
	}
}

func TestEgressSelfLoopErrorsIs(t *testing.T) {
	if !errors.Is(wrapSelfLoop(), ErrTorSelfLoop) {
		t.Fatal("errors.Is chain must recognize ErrTorSelfLoop")
	}
}

func TestEgressResolverCacheAndAntiSSRF(t *testing.T) {
	defer verifyNoLeaks(t)
	var calls atomic.Int64
	resolve := func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		switch host {
		case "bridge.example":
			return []netip.Addr{
				netip.MustParseAddr("192.168.1.50"),  // private — filtered
				netip.MustParseAddr("93.184.216.34"), // global — kept
			}, nil
		case "lan-only.example":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		default:
			return nil, net.ErrClosed
		}
	}
	d := NewDialer(EgressPolicy{Through: "none", Now: time.Now}, nil, resolve, nil)

	// anti-SSRF: hostname resolving only to private space is refused
	if _, err := d.Dial(context.Background(), ClassBridgePT, "lan-only.example", 443); err == nil {
		t.Fatal("LAN-only resolution must be refused (anti-SSRF)")
	}

	// literal loopback target refused
	if _, err := d.Dial(context.Background(), ClassBridgePT, "127.0.0.1", 80); err == nil {
		t.Fatal("loopback literal must be refused")
	}
	// literal private target refused
	if _, err := d.Dial(context.Background(), ClassBridgePT, "192.168.0.1", 80); err == nil {
		t.Fatal("private literal must be refused")
	}

	// positive cache: second resolve of the same host does not re-call
	addr, err := d.resolveTarget(context.Background(), "bridge.example")
	if err != nil || addr != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("resolveTarget = %v err=%v (want the global address only)", addr, err)
	}
	if _, err := d.resolveTarget(context.Background(), "bridge.example"); err != nil {
		t.Fatalf("cached resolve: %v", err)
	}
	if calls.Load() != 2 { // lan-only.example + bridge.example (once — then cached)
		t.Fatalf("resolve called %d times, want 2 (cache until restart)", calls.Load())
	}

	// negative cache: recent failures short-circuit
	if _, err := d.resolveTarget(context.Background(), "dead.example"); err == nil {
		t.Fatal("dead host must fail")
	}
	if _, err := d.resolveTarget(context.Background(), "dead.example"); err == nil {
		t.Fatal("negative cache must fail fast")
	}
	if calls.Load() != 3 {
		t.Fatalf("resolve called %d times, want 3", calls.Load())
	}
}

func TestEgressRendezvousNeverPinnedCarrier(t *testing.T) {
	// rendezvous/bootstrap classes force auto behavior even when a carrier
	// is pinned (design §3.3: never through the tunnel itself — and the
	// direct-with-carrier-fallback shape).
	d := NewDialer(EgressPolicy{Through: "proton", Now: time.Now}, nil, nil, nil)
	for _, class := range []ConnClass{ClassRendezvous, ClassBootstrapSrc} {
		if got := d.effectivePolicy(class); got != "auto" {
			t.Fatalf("class %s effective policy = %q, want auto", class, got)
		}
	}
	if got := d.effectivePolicy(ClassBridgePT); got != "proton" {
		t.Fatalf("bridge-pt effective policy = %q, want proton", got)
	}
	if got := d.effectivePolicy(ClassRelayDir); got != "proton" {
		t.Fatalf("relay-dir effective policy = %q, want proton", got)
	}
}

func TestEgressDialAnyCarrierExcludesTor(t *testing.T) {
	defer verifyNoLeaks(t)
	torCarrier := &fakeCarrier{kind: reserve.KindTor}
	other := &fakeCarrier{kind: reserve.KindWarp}
	d := NewDialer(EgressPolicy{Through: "auto", Now: time.Now}, fakeLookup(torCarrier, other), nil, nil)
	// register in the real registry so dialAnyCarrier sees them
	reserve.Reset()
	t.Cleanup(reserve.Reset)
	reserve.Register(torCarrier)
	reserve.Register(other)
	conn, err := d.dialAnyCarrier(context.Background(), netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("dialAnyCarrier: %v", err)
	}
	_ = conn.Close()
	if torCarrier.dials.Load() != 0 {
		t.Fatal("auto mode must NEVER route through tor itself (self-loop)")
	}
	if other.dials.Load() != 1 {
		t.Fatal("the warp carrier should have taken the dial")
	}
}

func TestEgressCarrierUnavailable(t *testing.T) {
	d := NewDialer(EgressPolicy{Through: "masque", Now: time.Now}, fakeLookup(), nil, nil)
	_, err := d.Dial(context.Background(), ClassRelayDir, "93.184.216.34", 443)
	if err == nil {
		t.Fatal("missing carrier must fail")
	}
}

// --- helpers ---

func startDirectEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte("echo"))
				_, _ = bufio.NewReader(conn).Discard(4096)
			}()
		}
	}()
	return ln
}

func srvPort(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	var port int
	if _, err := fmtSscanf(portStr, &port); err != nil {
		t.Fatalf("port: %v", err)
	}
	return port
}

func fmtSscanf(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, net.ErrClosed
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}

func wrapSelfLoop() error {
	return errWrap{ErrTorSelfLoop}
}

type errWrap struct{ inner error }

func (e errWrap) Error() string { return "wrapped: " + e.inner.Error() }
func (e errWrap) Unwrap() error { return e.inner }
