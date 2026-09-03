package opera

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validTestIdentity() *Identity {
	return &Identity{
		Format:             identityFormatVersion,
		SubscriberEmail:    "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpAb28@se0316.best.vpn",
		SubscriberPassword: capitalHexSHA1("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpAb28@se0316.best.vpn"),
		DeviceID:           deviceIDFix,
		DeviceIDHash:       capitalHexSHA1(deviceIDFix),
		DevicePassword:     jwtInitial,
		Pins:               map[string]string{"api2.sec-tunnel.com": strings.Repeat("ab", 32)},
		CreatedAt:          time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC),
		UpdatedAt:          time.Date(2026, 8, 25, 11, 0, 0, 0, time.UTC),
	}
}

func TestIdentityRoundTripAndQuarantine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "identity.json")
	store := &IdentityStore{Path: path}

	if _, err := store.Load(); !errors.Is(err, ErrIdentityAbsent) {
		t.Fatalf("absent load = %v", err)
	}

	id := validTestIdentity()
	if err := store.Save(id); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.DeviceIDHash != id.DeviceIDHash || got.SubscriberEmail != id.SubscriberEmail {
		t.Fatalf("round trip mismatch")
	}

	// Tampered hash must be rejected by derivation re-check.
	bad := validTestIdentity()
	bad.DeviceIDHash = "DEADBEEF"
	if err := bad.Validate(); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("tampered validate = %v", err)
	}
	if err := (&IdentityStore{Path: filepath.Join(t.TempDir(), "x.json")}).Save(bad); err == nil {
		t.Fatal("Save must reject invalid identity")
	}

	// Corrupt file -> quarantine, original preserved as evidence.
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrIdentityCorrupt) {
		t.Fatalf("corrupt load = %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("quarantine missing: %v", err)
	}
}

func TestIdentityRedacted(t *testing.T) {
	id := validTestIdentity()
	r := id.Redacted()
	for name, field := range map[string]string{
		"email":    r.SubscriberEmail,
		"subpass":  r.SubscriberPassword,
		"device":   r.DeviceID,
		"hash":     r.DeviceIDHash,
		"jwt":      r.DevicePassword,
	} {
		if field != "[redacted]" {
			t.Fatalf("%s not redacted: %q", name, field)
		}
	}
	for host, fp := range r.Pins {
		if want := strings.Repeat("ab", 6) + "…"; fp != want {
			t.Fatalf("pin fingerprint for %s = %q, want truncated %q", host, fp, want)
		}
	}
	// Original untouched.
	if id.DevicePassword != jwtInitial {
		t.Fatal("Redacted mutated source")
	}
}

func TestRegionGuards(t *testing.T) {
	if r, err := NormalizeRegion("eu"); err != nil || r != RegionEU {
		t.Fatalf("NormalizeRegion(eu) = %q, %v", r, err)
	}
	for _, bad := range []string{"RU", "", "US1", "europ"} {
		if _, err := NormalizeRegion(bad); err == nil {
			t.Fatalf("NormalizeRegion(%q) accepted", bad)
		}
	}
	if got := RegionArtifact(RegionAS); got != `"AS",,` {
		t.Fatalf("RegionArtifact = %q", got)
	}
}
