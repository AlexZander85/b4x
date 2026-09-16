package awgwarpservice

// Tests wire httptest for the enrollment API (the consent rule: no live
// Cloudflare traffic from unit tests). The session path is exercised only
// structurally — no wire handshakes in CI.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

func testConfig(identityPath string) *config.Config {
	c := config.NewConfig()
	c.System.Warp.AWG = config.WarpAWGConfig{
		Enabled:      true,
		IdentityPath: identityPath,
	}
	return &c
}

func enrollServer(t *testing.T, posts *atomic.Int64) *httptest.Server {
	// A non-zero edge public key (the identity validator rejects all-zero).
	edgePub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x0a}, 32))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0a4471/reg":
			posts.Add(1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if key, _ := body["key"].(string); key == "" {
				http.Error(w, "no key", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "awg-dev-1", "token": "awg-tok-1"})
		case "/v0a4471/reg/awg-dev-1":
			if r.Header.Get("Authorization") != "Bearer awg-tok-1" {
				http.Error(w, "auth", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"config": map[string]any{
					"client_id": "0102030405060708",
					"peers": []map[string]any{{
						"public_key": edgePub,
						"endpoint":   map[string]any{"v4": "162.159.193.5:2408"},
					}},
					"interface": map[string]any{
						"addresses": map[string]any{"v4": "172.16.0.2"},
					},
				},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func TestBuildDisabledZeroShape(t *testing.T) {
	c := config.NewConfig()
	rt, err := Build(&c, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v := rt.Status()
	if v.Enabled || v.Running || v.Listening {
		t.Fatalf("disabled shape must be inert: %+v", v)
	}
	if v.State != StateIdle {
		t.Fatalf("state = %q, want idle", v.State)
	}
}

func TestBuildBadEndpointFailsClosed(t *testing.T) {
	c := config.NewConfig()
	c.System.Warp.AWG.Endpoint = "8.8.8.8:2408" // outside the WG catalog
	if _, err := Build(&c, Options{}); err == nil {
		t.Fatal("out-of-catalog endpoint must fail the build")
	}
}

func TestEnsureIdentityEnrollsOnceAndPersists(t *testing.T) {
	var posts atomic.Int64
	srv := enrollServer(t, &posts)
	defer srv.Close()

	dir := t.TempDir()
	slot := filepath.Join(dir, "awg-identity.json")
	c := testConfig(slot)

	rt, err := Build(c, Options{
		HTTP:          srv.Client(),
		EnrollBaseURL: srv.URL + "/v0a4471",
		Now:           time.Now,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if err := rt.EnrollOnce(context.Background()); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts = %d, want 1", posts.Load())
	}
	v := rt.Status()
	if !v.IdentityPresent || v.AssignedV4 != "172.16.0.2" {
		t.Fatalf("identity not projected: %+v", v)
	}
	// The identity must be persisted to the slot.
	if _, err := os.Stat(slot); err != nil {
		t.Fatalf("slot not written: %v", err)
	}
	// A second ensure does NOT hit the API (identity in memory).
	if err := rt.EnrollOnce(context.Background()); err != nil {
		t.Fatalf("second enroll: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts after second ensure = %d, want 1", posts.Load())
	}
}

func TestEnsureIdentityLoadsStoredAndNeverReRegisters(t *testing.T) {
	var posts atomic.Int64
	srv := enrollServer(t, &posts)
	defer srv.Close()

	dir := t.TempDir()
	slot := filepath.Join(dir, "awg-identity.json")
	c := testConfig(slot)
	rt, err := Build(c, Options{HTTP: srv.Client(), EnrollBaseURL: srv.URL + "/v0a4471", Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := rt.EnrollOnce(context.Background()); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// A FRESH runtime over the same slot loads the stored identity and
	// never touches the API.
	rt2, err := Build(c, Options{HTTP: srv.Client(), EnrollBaseURL: srv.URL + "/v0a4471", Now: time.Now})
	if err != nil {
		t.Fatalf("build2: %v", err)
	}
	before := posts.Load()
	if err := rt2.EnrollOnce(context.Background()); err != nil {
		t.Fatalf("enroll2: %v", err)
	}
	if posts.Load() != before {
		t.Fatalf("stored identity path hit the API (%d -> %d)", before, posts.Load())
	}
	if v := rt2.Status(); !v.IdentityPresent {
		t.Fatal("stored identity not loaded")
	}
}

func TestCarrierRefusesWithoutEstablishedSession(t *testing.T) {
	dir := t.TempDir()
	c := testConfig(filepath.Join(dir, "slot.json"))
	rt, err := Build(c, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := rt.DialStream(context.Background(), mustAddr("93.184.216.34:443")); err == nil {
		t.Fatal("dial without a session must fail closed")
	}
	if rt.SupportsUDP() != true {
		t.Fatal("awg-warp advertises UDP full-scope")
	}
	if string(rt.Kind()) != "warp" {
		t.Fatalf("kind = %q", string(rt.Kind()))
	}
}

func TestDisabledConfigIsTruthfulNoOp(t *testing.T) {
	dir := t.TempDir()
	c := config.NewConfig()
	c.System.Warp.AWG.IdentityPath = filepath.Join(dir, "slot.json")
	rt, err := Build(&c, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Give the loop goroutine its first tick.
	time.Sleep(50 * time.Millisecond)
	rt.Stop()
	v := rt.Status()
	if v.State != StateStopped {
		t.Fatalf("state = %q, want stopped", v.State)
	}
	// No identity side effects on a disabled config.
	if _, err := os.Stat(filepath.Join(dir, "slot.json")); !os.IsNotExist(err) {
		t.Fatal("disabled config must not provision an identity")
	}
}

func mustAddr(s string) (ap netip.AddrPort) {
	return netip.MustParseAddrPort(s)
}
