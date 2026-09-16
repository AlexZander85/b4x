package nonruservice

// Tests: build validation (the base prerequisite, the endpoint gool rule),
// the waiting posture without a base identity, the assembly over the base
// plane (M+M + gate constructed, no live Cloudflare traffic — the parent-link
// controller honestly waits with the base supervisor stopped), the route
// promotion/revocation hooks against the reserve registry, the carrier
// honesty (IPv4/TCP posture) and the geo-transport down-path. The full
// composition lifecycle and the gate verdicts are covered by the engine's
// own e2e suites (transport/warp nonru tests, transport/nested M+M tests).
import (
	"context"
	"encoding/pem"
	"errors"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
	twarp "github.com/daniellavrushin/b4/transport/warp"
	"github.com/daniellavrushin/b4/warpservice"
)

// nonruTestConfig builds a config with the base warp enabled and the nonru
// section armed (heads only; callers mutate what they test).
func nonruTestConfig() *config.Config {
	c := config.NewConfig()
	c.System.Warp.Enabled = true
	c.System.Warp.IdentityPath = "/opt/etc/b4/warp/identity.json"
	c.System.Warp.NonRU.Enabled = true
	return &c
}

// nonruTestBase builds a warpservice runtime WITHOUT starting it (the base
// supervisor stays stopped: the parent-link controller waits, no network).
func nonruTestBase(t *testing.T, cfg *config.Config) *warpservice.Runtime {
	t.Helper()
	base, err := warpservice.Build(cfg, nil)
	if err != nil {
		t.Fatalf("base build: %v", err)
	}
	return base
}

// saveWarpIdentity writes a field-valid identity into a slot (the engine's
// own identity_test canon).
func saveWarpIdentity(t *testing.T, path string) {
	t.Helper()
	privB64, pubPKIX, err := twarp.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := twarp.ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	pinPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubPKIX}))
	ident := &twarp.Identity{
		Format:     twarp.IdentityFormatVersion,
		ID:         "dev-nonru-base",
		Token:      "tok-secret",
		PrivateKey: privB64,
		PinPEM:     pinPEM,
		PinDigest:  twarp.PinDigest(&priv.PublicKey),
		AssignedV4: "172.16.0.2",
	}
	if err := ident.Validate(); err != nil {
		t.Fatalf("identity invalid: %v", err)
	}
	if err := (&twarp.IdentityStore{Path: path}).Save(ident); err != nil {
		t.Fatalf("save identity: %v", err)
	}
}

func TestBuildRequiresBase(t *testing.T) {
	if _, err := Build(nonruTestConfig(), nil, Options{}); !errors.Is(err, ErrNoBase) {
		t.Fatalf("nil base must fail with ErrNoBase, got %v", err)
	}
}

func TestBuildRequiresBaseWarpEnabled(t *testing.T) {
	c := nonruTestConfig()
	c.System.Warp.Enabled = false // ADR-WARP-6: base WARP not ACTIVE
	if _, err := Build(c, nonruTestBase(t, c), Options{}); err == nil {
		t.Fatal("disabled base warp must fail the build")
	}
}

func TestBuildEndpointAvoidsBaseEdge(t *testing.T) {
	c := nonruTestConfig()
	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: func(netip.Addr) string { return "" }})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	baseAt, err := c.System.Warp.EffectiveEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if rt.innerAt.Addr() == baseAt.Addr() {
		t.Fatalf("inner default %v must avoid the base edge %v (gool rule)", rt.innerAt, baseAt)
	}
	if rt.innerAt.Addr() == netip.MustParseAddr("162.159.198.1") && baseAt.Addr() == netip.MustParseAddr("162.159.198.1") {
		t.Fatal("unreachable")
	}
	// The gate's probe plumbing is wired even with an all-unknown oracle.
	if _, err := rt.geoTransport(); !errors.Is(err, ErrInnerTransportDown) {
		t.Fatalf("geo transport without inner = %v, want ErrInnerTransportDown", err)
	}
}

func TestBuildOracleAbsenceIsHonestNotFatal(t *testing.T) {
	c := nonruTestConfig()
	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: nil, GeoIPPath: filepath.Join(t.TempDir(), "missing.dat")})
	if err != nil {
		t.Fatalf("missing geoip must not fail the build: %v", err)
	}
	if rt.oracleLoaded {
		t.Fatal("oracle must report not-loaded for a missing geoip.dat")
	}
	if got := rt.classifyFn()(netip.MustParseAddr("1.1.1.1")); got != "" {
		t.Fatalf("unloaded oracle classified %q, want \"\"", got)
	}
	v := rt.Status()
	if v.OracleLoaded {
		t.Fatal("status must surface oracle_loaded=false")
	}
}

func TestWaitsForBaseIdentity(t *testing.T) {
	c := nonruTestConfig()
	// The base slot points nowhere: the assembly must wait (no panic, no
	// partial composition — the chains' waiting-poster canon).
	c.System.Warp.IdentityPath = filepath.Join(t.TempDir(), "absent.json")
	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: func(netip.Addr) string { return "" }})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rt.tick(context.Background())

	rt.mu.Lock()
	composed, gated := rt.mm, rt.gate
	state := rt.state
	rt.mu.Unlock()
	if composed != nil || gated != nil {
		t.Fatalf("composition must not assemble without the base identity: mm=%v gate=%v", composed != nil, gated != nil)
	}
	if state != StateWaitingBase {
		t.Fatalf("state = %q, want %q", state, StateWaitingBase)
	}
	v := rt.Status()
	if v.Running || v.Listening {
		t.Fatalf("waiting posture leaked a running state: %+v", v)
	}
	// Stop is a safe no-op before Start.
	rt.Stop()
}

func TestAssemblesOverBasePlane(t *testing.T) {
	dir := t.TempDir()
	c := nonruTestConfig()
	c.System.Warp.IdentityPath = filepath.Join(dir, "base.json")
	saveWarpIdentity(t, c.System.Warp.IdentityPath)
	c.System.Warp.NonRU.IdentityPath = filepath.Join(dir, "nonru.json")

	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: func(netip.Addr) string { return "" }})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer rt.Stop()
	rt.tick(context.Background())

	rt.mu.Lock()
	composed, gated := rt.mm, rt.gate
	rt.mu.Unlock()
	if composed == nil || gated == nil {
		t.Fatal("the composition and the gate must assemble over the base plane")
	}
	v := rt.Status()
	if !v.Running {
		t.Fatalf("status must report the composition running: %+v", v)
	}
	if v.Listening {
		t.Fatalf("the gate must stay closed without a live inner path: %+v", v)
	}
	if v.State != StateUp {
		t.Fatalf("state = %q, want %q", v.State, StateUp)
	}
	if v.Gate.Providers != 3 {
		t.Fatalf("gate providers = %d, want 3 (2 whoami voters + cf-trace corroborator)", v.Gate.Providers)
	}
	if v.ParentGen != 0 {
		t.Fatalf("parent gen = %d, want 0 (no child started with the base down)", v.ParentGen)
	}
	// The inner supervisor is nil while the parent (base) is down.
	if rt.innerSupervisor() != nil {
		t.Fatal("inner supervisor must be nil with the base plane down")
	}
	// Stop tears the assembly down cleanly.
	rt.Stop()
	rt.mu.Lock()
	stoppedState := rt.state
	rt.mu.Unlock()
	if stoppedState != StateStopped {
		t.Fatalf("state after Stop = %q, want %q", stoppedState, StateStopped)
	}
}

func TestRoutePromotionRegistersCarrier(t *testing.T) {
	c := nonruTestConfig()
	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: func(netip.Addr) string { return "" }})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer rt.Stop()

	reserve.Reset()
	defer reserve.Reset()
	att := twarp.GeoAttestation{
		Class:        "non-ru",
		Country:      "DE",
		Providers:    2,
		Quorum:       2,
		PublicIPHash: "abcdef0123456789",
		PathID:       "path",
	}
	if err := rt.promoteRoute(att); err != nil {
		t.Fatalf("promote: %v", err)
	}
	e, ok := reserve.Lookup(reserve.KindNonRU)
	if !ok || e.Priority != reserve.PriorityNonRU {
		t.Fatalf("promotion must register kind=nonru with priority %d, got %+v", reserve.PriorityNonRU, e)
	}
	if e.Carrier != rt {
		t.Fatal("the promoted carrier must be the runtime itself")
	}
	if !rt.Status().Listening {
		t.Fatal("status must surface the open gate")
	}

	if err := rt.revokeRoute("provider-ru"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := reserve.Lookup(reserve.KindNonRU); ok {
		t.Fatal("revocation must unregister the carrier")
	}
	if rt.Status().Listening {
		t.Fatal("status must surface the closed gate")
	}
}

func TestCarrierPosture(t *testing.T) {
	c := nonruTestConfig()
	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: func(netip.Addr) string { return "" }})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer rt.Stop()

	if rt.Kind() != reserve.KindNonRU {
		t.Fatalf("kind = %q", string(rt.Kind()))
	}
	if rt.SupportsUDP() {
		t.Fatal("the inner MASQUE netstack v1 is IPv4/TCP only — SupportsUDP must be false")
	}
	if _, err := rt.DialUDP(context.Background(), netip.MustParseAddrPort("1.1.1.1:53")); !errors.Is(err, reserve.ErrCarrierNoUDP) {
		t.Fatalf("DialUDP = %v, want ErrCarrierNoUDP", err)
	}
	// No live inner layer: the honest refusal (never a nil conn).
	if _, err := rt.DialStream(context.Background(), netip.MustParseAddrPort("1.1.1.1:443")); !errors.Is(err, ErrNotListening) {
		t.Fatalf("DialStream without inner = %v, want ErrNotListening", err)
	}
}

func TestRestartNowRetiresAndCaps(t *testing.T) {
	c := nonruTestConfig()
	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: func(netip.Addr) string { return "" }})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer rt.Stop()
	// One restart past the cap: allowed (1), capped (2..7), allowed again?
	// The cap is restartCapPerHour per hour — exercise the boundary.
	for i := 0; i < restartCapPerHour; i++ {
		rt.RestartNow(context.Background())
	}
	rt.mu.Lock()
	restarts := rt.restarts
	rt.mu.Unlock()
	if restarts != restartCapPerHour {
		t.Fatalf("restarts = %d, want %d (all under the cap)", restarts, restartCapPerHour)
	}
	rt.RestartNow(context.Background()) // capped
	v := rt.Status()
	if v.State != StateCapped && v.Restarts != restartCapPerHour {
		t.Fatalf("restart past the cap must be refused: %+v", v)
	}
}

func TestStatusNilSafeEvents(t *testing.T) {
	c := nonruTestConfig()
	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: func(netip.Addr) string { return "" }})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer rt.Stop()
	v := rt.Status()
	if !v.Enabled || v.Running || v.Listening {
		t.Fatalf("fresh runtime must be inert: %+v", v)
	}
	if v.Gate.Open || v.Gate.Providers != 0 {
		t.Fatalf("fresh gate view must be zero: %+v", v.Gate)
	}
}

// TestPathSerialBumpsOnTransportFactory: the geo-transport factory is the
// CurrentGen source — the serial stays 0 while the inner is down and bumps
// per observed path identity (the transition itself is exercised by the
// engine's gate tests; here the down-path stability is pinned).
func TestPathSerialBumpsOnTransportFactory(t *testing.T) {
	c := nonruTestConfig()
	rt, err := Build(c, nonruTestBase(t, c), Options{Classify: func(netip.Addr) string { return "" }})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer rt.Stop()
	if got := rt.currentPathSerial(); got != 0 {
		t.Fatalf("serial = %d, want 0 while the inner is down", got)
	}
	if _, err := rt.geoTransport(); !errors.Is(err, ErrInnerTransportDown) {
		t.Fatalf("geo transport = %v, want ErrInnerTransportDown", err)
	}
	if got := rt.currentPathSerial(); got != 0 {
		t.Fatalf("serial must not move on the down-path: %d", got)
	}
}

// Compile-time sanity: the injected clock seam flows through the event ring.
func TestEventClockSeam(t *testing.T) {
	now := &atomic.Uint64{}
	c := nonruTestConfig()
	rt, err := Build(c, nonruTestBase(t, c), Options{
		Classify: func(netip.Addr) string { return "" },
		Now:      func() time.Time { return time.Unix(int64(now.Add(1)), 0) },
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer rt.Stop()
	rt.appendEvent(Event{Name: "test"})
	events := rt.Status().Events
	if len(events) == 0 || events[0].At == 0 {
		t.Fatal("event ring must carry the injected clock stamp")
	}
}
