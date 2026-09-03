package routing

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
)

type fallbackConn struct{ closed bool }

func (c *fallbackConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *fallbackConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *fallbackConn) Close() error                { c.closed = true; return nil }

func fallbackRequest() FlowRouteRequest {
	return FlowRouteRequest{
		SetID: "youtube-api", DeviceID: "android-a", Client: classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10")},
		Protocol: capture.ProtocolTCP, Family: capture.AddressFamilyIPv4, Phase: classifier.PhaseAmbiguous, Confidence: 50,
	}
}

func fallbackManager(t testing.TB, enabled bool, policy UnknownFlowPolicy) (*FallbackManager, *clock.FixedClock) {
	t.Helper()
	clk := clock.NewFixed(time.Unix(100, 0))
	m, err := NewFallbackManager(RouteConfig{Enabled: enabled, Policy: policy, ProcessedMark: 1 << 30, ProcessedMarkMask: 1 << 30, BypassMark: 1 << 29, GenericMark: 1 << 28, RuleTable: 100, ProxyRouteID: "proxy-a", Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return m, clk
}

func TestFallbackDecisionScopesConfidenceAndNoDoubleProcessing(t *testing.T) {
	m, _ := fallbackManager(t, true, UnknownRouteProxy)
	request := fallbackRequest()
	resolved := request
	resolved.Phase = classifier.PhaseResolved
	resolved.Confidence = 90
	decision, err := m.Decide(resolved)
	if err != nil || decision.Route != RouteNative || decision.NoDoubleProcess == false {
		t.Fatalf("resolved decision=%+v err=%v", decision, err)
	}
	if decision.SOMark != 0 || decision.RuleTable != 0 {
		t.Fatalf("native route was assigned fallback isolation: %+v", decision)
	}
	if err := m.SetHealth("proxy-a", true, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	decision, err = m.Decide(request)
	if err != nil || decision.Route != RouteProxy || decision.RouteID != "proxy-a" || decision.SOMark == 0 || decision.RuleTable != 100 || !decision.HealthOK {
		t.Fatalf("proxy decision=%+v err=%v", decision, err)
	}
	request.PacketMark = 1 << 30
	decision, err = m.Decide(request)
	if err != nil || decision.Route != RouteNative || decision.RouteID != "native" {
		t.Fatalf("processed packet was not bypassed: %+v err=%v", decision, err)
	}
	request = fallbackRequest()
	request.SetID = ""
	request.DeviceID = ""
	request.Client = classifier.ClientKey{}
	if _, err := m.Decide(request); !errors.Is(err, ErrRouteScopeRequired) {
		t.Fatalf("unscoped request error=%v", err)
	}
}

func TestFallbackHealthCooldownLastGoodAndDisabledFailOpen(t *testing.T) {
	m, clk := fallbackManager(t, true, UnknownRouteProxy)
	request := fallbackRequest()
	if err := m.SetHealth("proxy-a", false, clk.Now()); err != nil {
		t.Fatal(err)
	}
	decision, err := m.Decide(request)
	if err != nil || decision.Route != RouteDirect || decision.HealthOK {
		t.Fatalf("unhealthy proxy did not fail-open direct: %+v err=%v", decision, err)
	}
	scope := ScopeID(request.SetID, request.DeviceID, request.Client)
	if err := m.RecordSuccess(scope, "generic"); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordFailure(scope, "proxy-a"); err != nil {
		t.Fatal(err)
	}
	decision, err = m.Decide(request)
	if err != nil || decision.Route != RouteGeneric || !decision.LastGood || !decision.Cooldown {
		t.Fatalf("last-good route was not selected: %+v err=%v", decision, err)
	}
	clk.Advance(31 * time.Second)
	decision, err = m.Decide(request)
	if err != nil || decision.Cooldown {
		t.Fatalf("cooldown did not expire: %+v err=%v", decision, err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	disabled, _ := fallbackManager(t, false, UnknownRouteProxy)
	decision, err = disabled.Decide(request)
	if err != nil || decision.Route != RouteDirect {
		t.Fatalf("disabled fallback was not direct fail-open: %+v err=%v", decision, err)
	}
}

func TestFallbackPoolAndUDPSessionsAreBoundedAndExpiring(t *testing.T) {
	m, clk := fallbackManager(t, true, UnknownUseGeneric)
	pool := m.Pool()
	key := PoolKey{ScopeID: "scope-a", RouteID: "proxy-a", Network: "tcp", Target: "api.youtube.com:443"}
	conn := &fallbackConn{}
	if err := pool.Put(key, conn); err != nil {
		t.Fatal(err)
	}
	got, ok := pool.Get(key)
	if !ok || got != conn {
		t.Fatalf("pooled connection=%v ok=%v", got, ok)
	}
	if err := pool.Put(key, conn); err != nil {
		t.Fatal(err)
	}
	clk.Advance(6 * time.Minute)
	if removed := pool.GC(clk.Now()); removed != 1 || !conn.closed {
		t.Fatalf("pool expiry removed=%d closed=%v", removed, conn.closed)
	}
	udp := NewUDPSessionStore(1, time.Second, clk)
	if !udp.Touch("scope-a|flow-a", clk.Now()) || udp.Len() != 1 || udp.Touch("scope-b|flow-b", clk.Now()) {
		t.Fatalf("UDP bounds failed len=%d", udp.Len())
	}
	clk.Advance(2 * time.Second)
	if removed := udp.GC(clk.Now()); removed != 1 || udp.Len() != 0 {
		t.Fatalf("UDP expiry removed=%d len=%d", removed, udp.Len())
	}
}

func TestFallbackValidationAndHealthProbe(t *testing.T) {
	if _, err := NewFallbackManager(RouteConfig{Policy: UnknownRouteProxy}); !errors.Is(err, ErrRouteInvalid) {
		t.Fatalf("proxy route validation error=%v", err)
	}
	m, _ := fallbackManager(t, true, UnknownRouteProxy)
	called := false
	err := m.HealthCheck(nil, "proxy-a", func(_ context.Context, routeID string) error {
		called = routeID == "proxy-a"
		return nil
	})
	if err != nil || !called {
		t.Fatalf("health probe err=%v called=%v", err, called)
	}
}

func TestFallbackGC(t *testing.T) {
	m, clk := fallbackManager(t, true, UnknownRouteProxy)
	if err := m.RecordSuccess("scope-a", "proxy-a"); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordFailure("scope-a", "proxy-a"); err != nil {
		t.Fatal(err)
	}
	pool := m.Pool()
	if err := pool.Put(PoolKey{ScopeID: "scope-a", RouteID: "proxy-a", Network: "tcp", Target: "api.youtube.com:443"}, &fallbackConn{}); err != nil {
		t.Fatal(err)
	}
	if m.GC(clk.Now()) != 0 {
		t.Fatalf("GC removed live last-good/cooldown entries")
	}
	clk.Advance(31 * time.Second) // past cooldown and last-good TTL (5m not reached, cooldown 30s is)
	if m.GC(clk.Now()) == 0 {
		t.Fatalf("GC did not remove expired cooldown entry")
	}
}

func FuzzFallbackDecisionNoPanic(f *testing.F) {
	f.Add(uint8(90), uint8(capture.ProtocolTCP), uint8(capture.AddressFamilyIPv4), uint8(classifier.PhaseResolved))
	f.Add(uint8(1), uint8(capture.ProtocolUDP), uint8(capture.AddressFamilyIPv6), uint8(classifier.PhaseAmbiguous))
	f.Fuzz(func(t *testing.T, confidence, protocol, family, phase uint8) {
		m, _ := fallbackManager(t, true, UnknownRouteProxy)
		request := fallbackRequest()
		request.Confidence = confidence
		request.Protocol = protocol
		request.Family = capture.AddressFamily(family)
		request.Phase = classifier.ClassificationPhase(phase)
		_, _ = m.Decide(request)
	})
}

func BenchmarkFallbackDecision(b *testing.B) {
	m, _ := fallbackManager(b, true, UnknownRouteProxy)
	request := fallbackRequest()
	if err := m.SetHealth("proxy-a", true, time.Unix(100, 0)); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = m.Decide(request)
	}
}
