package proton

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// testSeed is a fixed 32-byte seed so every expectation in this file is
// reproducible.
var testSeed = [32]byte{
	0xA5, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
	0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
}

// TestDeriveKeyPairGoldenPEM pins the wire shape Proton's
// /vpn/v1/certificate expects (Nova ed25519PublicKeyPem): PEM-wrapped
// SubjectPublicKeyInfo whose base64 body is the fixed RFC 8410 DER prefix
// "MCowBQYDK2VwAyEA" (12 bytes) + base64(ed25519 pub). The public key is
// re-derived through the stdlib independently of the PEM assembly code.
func TestDeriveKeyPairGoldenPEM(t *testing.T) {
	kp := DeriveKeyPair(testSeed)

	if !strings.HasPrefix(kp.Ed25519PubPEM, "-----BEGIN PUBLIC KEY-----\n") ||
		!strings.HasSuffix(kp.Ed25519PubPEM, "\n-----END PUBLIC KEY-----\n") {
		t.Fatalf("unexpected PEM framing: %q", kp.Ed25519PubPEM)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(kp.Ed25519PubPEM, "-----BEGIN PUBLIC KEY-----\n"), "\n-----END PUBLIC KEY-----\n")
	if !strings.HasPrefix(body, "MCowBQYDK2VwAyEA") {
		t.Fatalf("PEM body missing the fixed ed25519 SPKI prefix: %q", body)
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("PEM body is not base64: %v", err)
	}
	if len(raw) != 44 {
		t.Fatalf("SPKI body must decode to 12+32 bytes, got %d", len(raw))
	}
	// The 12-byte DER header bytes (30 2A 30 05 06 03 2B 65 70 03 21 00).
	wantDER := []byte{0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00}
	if !bytes.Equal(raw[:12], wantDER) {
		t.Fatalf("DER header mismatch: got %x want %x", raw[:12], wantDER)
	}

	// Independent pub derivation via crypto/ed25519.
	priv := ed25519.NewKeyFromSeed(testSeed[:])
	wantPub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(raw[12:], wantPub) {
		t.Fatalf("ed25519 pub mismatch: got %x want %x", raw[12:], wantPub)
	}

	// Determinism: the same seed always yields the same identity.
	if again := DeriveKeyPair(testSeed); again.Ed25519PubPEM != kp.Ed25519PubPEM || again.WGPrivateKeyB64 != kp.WGPrivateKeyB64 {
		t.Fatal("DeriveKeyPair is not deterministic")
	}
}

// TestWGPrivateKeyClamp pins the ed25519->x25519 conversion:
// priv = clamp(SHA-512(seed)[0:32]) with priv[0]&=248, priv[31]&=127,
// priv[31]|=64 (Nova wireGuardPrivateKeyBase64:70-77).
func TestWGPrivateKeyClamp(t *testing.T) {
	kp := DeriveKeyPair(testSeed)
	priv, err := base64.StdEncoding.DecodeString(kp.WGPrivateKeyB64)
	if err != nil {
		t.Fatalf("wg private key not base64: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("wg private key must be 32 bytes, got %d", len(priv))
	}
	h := sha512.Sum512(testSeed[:])
	want := h[:32]
	want[0] &= 248
	want[31] &= 127
	want[31] |= 64
	if !bytes.Equal(priv, want) {
		t.Fatalf("clamped private key mismatch: got %x want %x", priv, want)
	}
	// The x25519 public half must be a non-trivial stable value.
	if kp.WGPubKeyB64 == "" || kp.WGPubKeyB64 == base64.StdEncoding.EncodeToString(make([]byte, 32)) {
		t.Fatal("wg public key empty or zero")
	}
}

func TestRandomSeed(t *testing.T) {
	r := bytes.NewReader(bytes.Repeat([]byte{0x42}, 32))
	seed, err := RandomSeed(r)
	if err != nil {
		t.Fatalf("RandomSeed: %v", err)
	}
	for i, b := range seed {
		if b != 0x42 {
			t.Fatalf("seed[%d]=%02x want 0x42", i, b)
		}
	}
	// Under-read is an error, not silence.
	if _, err := RandomSeed(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("RandomSeed must fail on short reader")
	}
}

// ---- identity store -------------------------------------------------------------

func testIdentity(t *testing.T) *Identity {
	t.Helper()
	kp := DeriveKeyPair(testSeed)
	return &Identity{
		SeedB64:          base64.StdEncoding.EncodeToString(testSeed[:]),
		DeviceProfile:    DeviceProfile{Model: "Pixel 7", AndroidVersion: "13", Language: "fr", RegionCode: "FR", Timezone: "Europe/Paris", TimezoneOffset: -60, StorageBytes: 6.4e10, DeviceNameHash: 3746281946382741, Keyboards: []string{"com.google.android.inputmethod.latin"}},
		UID:              "uid-value",
		AccessToken:      "access-value",
		RefreshToken:     "refresh-value",
		RegisteredPubPEM: kp.Ed25519PubPEM,
		CertExpiresAt:    1800000000,
		CertRefreshAt:    1780000000,
	}
}

func TestIdentityStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := &IdentityStore{Path: filepath.Join(dir, "identity.json")}

	if _, err := store.Load(); !errors.Is(err, ErrIdentityAbsent) {
		t.Fatalf("absent load: got %v want ErrIdentityAbsent", err)
	}

	id := testIdentity(t)
	id.CreatedAt = 1700000000
	id.UpdatedAt = 1700000100
	if err := store.Save(id); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.UID != id.UID || loaded.AccessToken != id.AccessToken || loaded.RefreshToken != id.RefreshToken {
		t.Fatal("session material lost on round-trip")
	}
	if !reflect.DeepEqual(loaded.DeviceProfile, id.DeviceProfile) {
		t.Fatalf("device profile lost: %+v != %+v", loaded.DeviceProfile, id.DeviceProfile)
	}
	if loaded.RegisteredPubPEM != id.RegisteredPubPEM {
		t.Fatal("registered PEM lost")
	}

	// 0600 on the secret file (Linux production target).
	fi, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("identity file mode %o, want 600", perm)
	}
}

func TestIdentityStoreQuarantine(t *testing.T) {
	dir := t.TempDir()
	store := &IdentityStore{Path: filepath.Join(dir, "identity.json")}

	// Unparseable JSON -> quarantine + ErrIdentityCorrupt.
	if err := os.WriteFile(store.Path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrIdentityCorrupt) {
		t.Fatalf("corrupt load: got %v want ErrIdentityCorrupt", err)
	}
	if _, err := os.Stat(store.Path + ".corrupt"); err != nil {
		t.Fatalf("quarantine file missing: %v", err)
	}
	if _, err := os.Stat(store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original file must be gone after quarantine")
	}

	// Valid JSON but tampered seed -> ErrIdentityInvalid + quarantine.
	bad := testIdentity(t)
	bad.SeedB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err := os.WriteFile(store.Path, mustJSON(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("tampered load: got %v want ErrIdentityInvalid", err)
	}

	// Valid JSON but PEM from a DIFFERENT seed -> ErrIdentityInvalid.
	other := DeriveKeyPair([32]byte{})
	tampered := testIdentity(t)
	tampered.RegisteredPubPEM = other.Ed25519PubPEM
	if err := os.WriteFile(store.Path, mustJSON(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("cross-seed load: got %v want ErrIdentityInvalid", err)
	}
}

func TestIdentityRedacted(t *testing.T) {
	id := testIdentity(t)
	red := id.Redacted()

	// The redacted shape must not carry any secret material.
	blob, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{id.SeedB64, id.AccessToken, id.RefreshToken, id.UID, id.RegisteredPubPEM} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("redacted identity leaks %q", secret)
		}
	}
	if !red.HasSeed || !red.HasSession {
		t.Fatalf("redacted flags wrong: %+v", red)
	}
	// pubkey_prefix = first 12 chars of the PEM body (fixed DER prefix).
	if !strings.HasPrefix(red.PubkeyPrefix, "MCowBQYDK2Vw") {
		t.Fatalf("unexpected pubkey prefix %q", red.PubkeyPrefix)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
