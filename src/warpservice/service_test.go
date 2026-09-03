package warpservice

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
	warp "github.com/daniellavrushin/b4/transport/warp"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	c := config.NewConfig()
	c.System.Warp.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	return &c
}

// Build must succeed even with Enabled=false: CLI enrollment (field session
// phase B) runs BEFORE the transport switch, so the runtime cannot require
// the enabled flag.
func TestBuildConstructsWithoutEnabledFlag(t *testing.T) {
	c := testConfig(t)
	rt, err := Build(c, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rt == nil {
		t.Fatal("nil runtime")
	}
	if st := rt.Status().Status; st.RouteHeld {
		t.Fatal("fresh runtime must not hold a route")
	}
}

func TestBuildRejectsNonCatalogEndpoint(t *testing.T) {
	c := testConfig(t)
	c.System.Warp.Endpoint = "1.2.3.4:443"
	if _, err := Build(c, nil); err == nil {
		t.Fatal("non-catalog endpoint must fail closed at build time")
	}
}

func TestStopBeforeStartIsNoop(t *testing.T) {
	c := testConfig(t)
	rt, err := Build(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.Stop() // must not panic
}

// validTestIdentity builds an identity the engine store accepts on Load.
// GenerateClientKey returns raw PKIX DER; the identity PinPEM field carries
// the PEM wrapper exactly as the registration flow stores it.
func validTestIdentity(t *testing.T) *warp.Identity {
	t.Helper()
	privB64, pubDER, err := warp.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	pinPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	_, digest, err := warp.ParsePublicKeyPEM(pinPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &warp.Identity{
		ID:         "dev-test-1",
		Token:      "SUPERSECRETTOKEN",
		PrivateKey: privB64,
		PinPEM:     pinPEM,
		PinDigest:  digest,
		AssignedV4: "100.96.0.5",
	}
}

// Summaries carry derived identifiers only; token/key/PEM/full digest never
// reach CLI output (grep control of field session phase B).
func TestSummariesRedactSecrets(t *testing.T) {
	ident := validTestIdentity(t)

	var s Summary
	fillFromIdentity(&s, ident)
	blob, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{ident.Token, ident.PrivateKey, ident.PinPEM, ident.PinDigest} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("summary leaks secret %q...: %s", secret[:8], blob)
		}
	}
	if s.PinDigestPrefix != ident.PinDigest[:pinDigestPrefixLen] {
		t.Fatalf("pin digest prefix = %q", s.PinDigestPrefix)
	}

	res := warp.EnsureResult{Action: warp.ActionProvisioned, Identity: ident}
	es := EnrollSummary(res, "/opt/etc/b4/warp/identity.json")
	blob2, _ := json.Marshal(es)
	for _, secret := range []string{ident.Token, ident.PrivateKey, ident.PinPEM} {
		if strings.Contains(string(blob2), secret) {
			t.Fatalf("enroll summary leaks secret: %s", blob2)
		}
	}
	if es.Action != string(warp.ActionProvisioned) || es.State != "present" {
		t.Fatalf("enroll summary fields wrong: %+v", es)
	}
}

func TestOfflineSummaryStates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "identity.json")

	if got := OfflineSummary(p); got.State != "absent" {
		t.Fatalf("missing file state = %q, want absent", got.State)
	}

	store := &warp.IdentityStore{Path: p}
	if err := store.Save(validTestIdentity(t)); err != nil {
		t.Fatal(err)
	}
	got := OfflineSummary(p)
	if got.State != "present" || got.DeviceID != "dev-test-1" {
		t.Fatalf("present summary wrong: %+v", got)
	}
	if strings.Contains(got.DeviceID, "SUPERSECRETTOKEN") {
		t.Fatal("unexpected token leak")
	}

	// Corrupt store is reported structurally (engine quarantines on Load).
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got = OfflineSummary(p)
	if got.State != "invalid" || !got.Quarantined {
		t.Fatalf("corrupt store state = %+v, want invalid+quarantined", got)
	}
}
