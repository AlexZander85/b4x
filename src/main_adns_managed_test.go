package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/managed"
)

func TestBuildADNSManagedProvidersRequiresCompleteVerifiedMaterial(t *testing.T) {
	t.Setenv(managedDNSBinaryEnv, "/does/not/exist")
	t.Setenv(managedDNSManifestEnv, "")
	if got := buildADNSManagedProviders(dnspath.DefaultAdaptivePolicy(), "example.com"); len(got) != 0 {
		t.Fatalf("partial managed deployment must fail closed, got %d providers", len(got))
	}
}

func TestBuildADNSManagedProvidersFromSignedStampedCatalog(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "dnscrypt-proxy")
	if err := os.WriteFile(binaryPath, []byte("fixture-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	sum, err := managed.HashFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := managed.BinaryManifest{
		Version: "fixture", Commit: managed.PinnedCommit, License: managed.PinnedLicense,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, SHA256: sum, BuildRecord: "test-build",
	}
	manifestBytes, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	catalog := []byte("version|managed-test-v1\nresolver-a|dnscrypt|true|true|true|sdns://AQcAAAAAAAAAAA\n")
	catalogPath := filepath.Join(dir, "catalog.txt")
	if err := os.WriteFile(catalogPath, catalog, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sig := managed.SignaturePayload{
		PublicKey: pubB64,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, catalog)),
	}
	sigBytes, _ := json.Marshal(sig)
	sigPath := filepath.Join(dir, "catalog.sig.json")
	if err := os.WriteFile(sigPath, sigBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(managedDNSBinaryEnv, binaryPath)
	t.Setenv(managedDNSManifestEnv, manifestPath)
	t.Setenv(managedDNSCatalogEnv, catalogPath)
	t.Setenv(managedDNSCatalogSigEnv, sigPath)
	t.Setenv(managedDNSCatalogKeyEnv, pubB64)
	t.Setenv(managedDNSWorkDirEnv, filepath.Join(dir, "work"))

	policy := dnspath.DefaultAdaptivePolicy()
	got := buildADNSManagedProviders(policy, "example.com")
	if len(got) != 1 {
		t.Fatalf("verified stamped catalog should yield one provider, got %d", len(got))
	}
	caps := got[0].Capabilities()
	if caps.State != dnspath.CapAvailable || !caps.CatalogTrusted || !caps.DNSSEC || !caps.NoLogClaim || !caps.NoFilterClaim {
		t.Fatalf("managed capability provenance mismatch: %+v", caps)
	}
	if got[0].ID().CatalogVersion != "managed-test-v1" {
		t.Fatalf("provider catalog version=%q", got[0].ID().CatalogVersion)
	}
}
