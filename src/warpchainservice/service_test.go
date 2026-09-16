package warpchainservice

// Tests: build/validation matrices for both compositions, the carrier
// honesty (UDP posture per kind), the wg identity slot discipline (stored
// identity loads, one registration per boot through the httptest seam) and
// the waiting posture when the outer MASQUE slot is not provisioned yet.
// NO live Cloudflare traffic originates here (the consent rule); the full
// composition lifecycle is covered by the nested engine's own e2e tests.
import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

func chainCfg(dir, kind string) config.WarpChainConfig {
	return config.WarpChainConfig{
		Kind:              kind,
		Enabled:           true,
		OuterIdentityPath: filepath.Join(dir, kind+"-outer.json"),
		InnerIdentityPath: filepath.Join(dir, kind+"-inner.json"),
	}
}

func testConfig(chain config.WarpChainConfig) *config.Config {
	c := config.NewConfig()
	c.System.Warp.Chains = []config.WarpChainConfig{chain}
	return &c
}

func TestBuildBothCompositions(t *testing.T) {
	dir := t.TempDir()
	for _, kind := range config.WarpChainKinds {
		ch := chainCfg(dir, kind)
		rt, err := Build(testConfig(ch), ch, Options{Now: time.Now})
		if err != nil {
			t.Fatalf("build %s: %v", kind, err)
		}
		if rt.Kind() != reserve.Kind(kind) {
			t.Fatalf("kind = %q, want %q", string(rt.Kind()), kind)
		}
		// The AWG layer slot is inner for masque+awg, outer for awg+masque.
		if rt.wgStore.Path == "" {
			t.Fatalf("awg slot not resolved for %s", kind)
		}
		v := rt.Status()
		if v.Enabled != true || v.Running || v.Listening {
			t.Fatalf("fresh runtime must be inert: %+v", v)
		}
	}
}

func TestBuildRejectsBadKind(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, "masque+masque")
	if _, err := Build(testConfig(ch), ch, Options{}); err == nil {
		t.Fatal("engine-pending kind must fail the build")
	}
}

func TestBuildWgWg(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindAwgAwg)
	ch.AWGProfile = "quic-a" // junk-active outer (the W+W requirement)
	rt, err := Build(testConfig(ch), ch, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build w+w: %v", err)
	}
	if rt.Kind() != reserve.KindChainAwgAwg {
		t.Fatalf("kind = %q, want awg+awg", string(rt.Kind()))
	}
	// TWO wg slots: the outer in wgStore, the inner in wgInnerStore, on
	// DISTINCT paths (one CF device per layer — red line #3).
	if rt.wgStore.Path != ch.EffectiveOuterIdentityPath() {
		t.Fatalf("outer slot = %q, want %q", rt.wgStore.Path, ch.EffectiveOuterIdentityPath())
	}
	if rt.wgInnerStore == nil || rt.wgInnerStore.Path != ch.EffectiveInnerIdentityPath() {
		t.Fatalf("inner slot = %v, want %q", rt.wgInnerStore, ch.EffectiveInnerIdentityPath())
	}
	if rt.wgStore.Path == rt.wgInnerStore.Path {
		t.Fatal("W+W slots must be distinct")
	}
	if rt.outerSup != nil {
		t.Fatal("W+W owns no masque supervisor")
	}
	v := rt.Status()
	if v.Enabled != true || v.Running || v.Listening {
		t.Fatalf("fresh runtime must be inert: %+v", v)
	}
}

func TestBuildWgWgRejectsFingerprint(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindAwgAwg)
	ch.AWGProfile = "quic-a"
	ch.Fingerprint = "chrome120" // no masque layer in W+W
	if _, err := Build(testConfig(ch), ch, Options{}); err == nil {
		t.Fatal("fingerprint on a W+W chain must fail the build")
	}
}

func TestCarrierUDPPostureWgWg(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindAwgAwg)
	ch.AWGProfile = "quic-a"
	rt, err := Build(testConfig(ch), ch, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build w+w: %v", err)
	}
	if !rt.SupportsUDP() {
		t.Fatal("awg+awg must advertise UDP (inner AWG netstack)")
	}
	// Without a live composition both legs fail closed.
	if _, err := rt.DialStream(context.Background(), mustAP("93.184.216.34:443")); err == nil {
		t.Fatal("stream dial without a composition must fail closed")
	}
	if _, err := rt.DialUDP(context.Background(), mustAP("93.184.216.34:443")); err == nil {
		t.Fatal("udp dial without a composition must fail closed")
	}
}

func TestBuildRejectsCrossCatalogEndpoint(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindMasqueAwg)
	ch.OuterEndpoint = "162.159.193.5:443" // WG catalog, not MASQUE
	if _, err := Build(testConfig(ch), ch, Options{}); err == nil {
		t.Fatal("cross-catalog endpoint must fail the build")
	}
}

func TestBuildRejectsNonCfWarpProfile(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindMasqueAwg)
	ch.AWGProfile = "awg-sh-a" // plan Б S/H family — not for the CF edge
	if _, err := Build(testConfig(ch), ch, Options{}); err == nil {
		t.Fatal("non-cf-warp profile must fail the build")
	}
}

func TestCarrierUDPPosture(t *testing.T) {
	dir := t.TempDir()
	// masque+awg: the inner AWG netstack carries UDP.
	chMw := chainCfg(dir, config.ChainKindMasqueAwg)
	rtMw, err := Build(testConfig(chMw), chMw, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build m+w: %v", err)
	}
	if !rtMw.SupportsUDP() {
		t.Fatal("masque+awg must advertise UDP (inner AWG netstack)")
	}
	// awg+masque: the inner MASQUE netstack v1 is IPv4/TCP only.
	chWm := chainCfg(dir, config.ChainKindAwgMasque)
	rtWm, err := Build(testConfig(chWm), chWm, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build w+m: %v", err)
	}
	if rtWm.SupportsUDP() {
		t.Fatal("awg+masque must NOT advertise UDP (netstack v1)")
	}
	if _, err := rtWm.DialUDP(context.Background(), mustAP("93.184.216.34:443")); !errors.Is(err, reserve.ErrCarrierNoUDP) {
		t.Fatalf("udp dial must refuse with ErrCarrierNoUDP, got %v", err)
	}
}

func TestDialFailsClosedWithoutComposition(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindMasqueAwg)
	rt, err := Build(testConfig(ch), ch, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := rt.DialStream(context.Background(), mustAP("93.184.216.34:443")); err == nil {
		t.Fatal("dial without a composition must fail closed")
	}
}

func TestEnsureWGIdentityLoadsStored(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindMasqueAwg)

	// Provision a valid wg identity through the store API (the canonical
	// serialization — no hand-rolled JSON).
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	ident, err := twg.NewIdentity(
		twg.Key(priv).B64(),
		twg.Key(priv).Pub().B64(),
		"AAECAw==",
		"172.16.0.2", "", true,
	)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := (&twg.IdentityStore{Path: ch.EffectiveInnerIdentityPath()}).Save(ident); err != nil {
		t.Fatalf("save: %v", err)
	}

	rt, err := Build(testConfig(ch), ch, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := rt.ensureWGIdentity(context.Background())
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if got == nil || got.AssignedV4 != "172.16.0.2" {
		t.Fatalf("stored identity not loaded: %+v", got)
	}
}

func TestEnsureWGIdentityRegistersOncePerBoot(t *testing.T) {
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0a4471/reg":
			posts.Add(1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if key, _ := body["key"].(string); key == "" {
				http.Error(w, "no key", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "c1", "token": "t1"})
		case "/v0a4471/reg/c1":
			if r.Header.Get("Authorization") != "Bearer t1" {
				http.Error(w, "auth", http.StatusUnauthorized)
				return
			}
			pub := make([]byte, 32)
			for i := range pub {
				pub[i] = byte(i + 3)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"config": map[string]any{
					"client_id": "0102030405",
					"peers":     []map[string]any{{"public_key": mustB64(pub)}},
					"interface": map[string]any{
						"addresses": map[string]any{"v4": "172.16.0.9"},
					},
				},
			})
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindMasqueAwg)
	rt, err := Build(testConfig(ch), ch, Options{
		HTTP:            srv.Client(),
		WGEnrollBaseURL: srv.URL + "/v0a4471",
		Now:             time.Now,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := rt.ensureWGIdentity(context.Background())
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if got == nil || got.AssignedV4 != "172.16.0.9" {
		t.Fatalf("registration did not project: %+v", got)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts = %d, want 1", posts.Load())
	}
	// The identity is persisted (a second ensure hits only the store).
	if _, err := os.Stat(ch.EffectiveInnerIdentityPath()); err != nil {
		t.Fatalf("slot not written: %v", err)
	}
	if _, err := rt.ensureWGIdentity(context.Background()); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts after second ensure = %d, want 1", posts.Load())
	}
}

func TestMasqueAwgWaitsForOuterIdentity(t *testing.T) {
	dir := t.TempDir()
	ch := chainCfg(dir, config.ChainKindMasqueAwg)

	// Inner AWG identity present, outer MASQUE slot ABSENT: the composition
	// must wait (no panic, no partial assembly, an honest waiting state).
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	ident, err := twg.NewIdentity(twg.Key(priv).B64(), twg.Key(priv).Pub().B64(),
		"AAECAw==", "172.16.0.2", "", true)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := (&twg.IdentityStore{Path: ch.EffectiveInnerIdentityPath()}).Save(ident); err != nil {
		t.Fatalf("save: %v", err)
	}

	rt, err := Build(testConfig(ch), ch, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// The tick would normally run under Start; call it directly WITHOUT
	// starting the outer supervisor (no network in CI).
	rt.tick(context.Background())

	rt.mu.Lock()
	composed := rt.mPlusW
	rt.mu.Unlock()
	if composed != nil {
		t.Fatal("composition must not assemble without the outer identity")
	}
	v := rt.Status()
	if v.Running || v.Listening {
		t.Fatalf("waiting posture leaked a running state: %+v", v)
	}
	// Stop is a safe no-op before Start.
	rt.Stop()
}

func mustAP(s string) (ap netip.AddrPort) { return netip.MustParseAddrPort(s) }

func mustB64(b []byte) string {
	return twg.Key(b).B64()
}
