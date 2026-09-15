package managed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func manifestFor(t *testing.T, binaryPath string) BinaryManifest {
	t.Helper()
	sum, err := HashFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	return BinaryManifest{
		Version: "2.1.5", Commit: PinnedCommit, License: PinnedLicense,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		SHA256: sum, BuildRecord: "pinned-build-1",
	}
}

func sleepBinary(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/sleep", "/usr/bin/sleep"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("sleep binary not available")
	return ""
}

func TestVerifyBinary(t *testing.T) {
	bin := sleepBinary(t)
	m := manifestFor(t, bin)
	if err := VerifyBinary(bin, m); err != nil {
		t.Fatalf("pinned binary must verify: %v", err)
	}
}

func TestVerifyBinaryRejectsTampering(t *testing.T) {
	bin := sleepBinary(t)
	m := manifestFor(t, bin)
	m.SHA256 = strings.Repeat("0", 64)
	if err := VerifyBinary(bin, m); !errors.Is(err, ErrUnverifiedBinary) {
		t.Fatal("hash mismatch must be rejected (dns_unverified_backend_binary_total)")
	}
	m = manifestFor(t, bin)
	m.Commit = "deadbeef"
	if err := VerifyBinary(bin, m); !errors.Is(err, ErrUnverifiedBinary) {
		t.Fatal("unpinned commit must be rejected")
	}
	m = manifestFor(t, bin)
	m.GOARCH = "mipsle"
	if err := VerifyBinary(bin, m); !errors.Is(err, ErrUnverifiedBinary) {
		t.Fatal("foreign platform must be rejected")
	}
	m = manifestFor(t, bin)
	m.License = "GPL-3.0"
	if err := VerifyBinary(bin, m); !errors.Is(err, ErrUnverifiedBinary) {
		t.Fatal("license mismatch must be rejected")
	}
}

func specFixture(listen string) InstanceSpec {
	return InstanceSpec{
		Family: "dnscrypt", ServerName: "reviewed-server-a",
		ListenAddr: listen, IPv4: true, Cache: true, CacheSize: 256,
		RequireNoLog: true, RequireNoFilter: true,
	}
}

func TestGenerateConfigSingleCausalResolver(t *testing.T) {
	cfg, err := GenerateConfig(specFixture("127.0.0.1:55331"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "server_names = ['reviewed-server-a']") {
		t.Fatal("config must pin exactly one explicit server")
	}
	if !strings.Contains(cfg, "lb_strategy = 'first'") || !strings.Contains(cfg, "lb_estimator = false") {
		t.Fatal("hidden multi-server random selection must be impossible")
	}
	if !strings.Contains(cfg, "listen_addresses = ['127.0.0.1:55331']") {
		t.Fatal("listener must be loopback-owned")
	}
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "query_log") || strings.HasPrefix(line, "edns_client_subnet") {
			t.Fatalf("privacy-prohibited key must stay unset, got %q", line)
		}
	}
	if err := ValidateKeys(cfg); err != nil {
		t.Fatalf("generated config must pass key validation: %v", err)
	}
}

func TestGenerateConfigRejectsNonLoopback(t *testing.T) {
	s := specFixture("0.0.0.0:55331")
	if _, err := GenerateConfig(s); err == nil {
		t.Fatal("LAN-exposed listener must be rejected")
	}
}

func TestGenerateConfigRejectsRelayMismatch(t *testing.T) {
	s := specFixture("127.0.0.1:55331")
	s.RelayName = "relay-x"
	if _, err := GenerateConfig(s); err == nil {
		t.Fatal("plain dnscrypt must not bind a relay")
	}
	s = specFixture("127.0.0.1:55331")
	s.Family = "anonymized-dnscrypt"
	if _, err := GenerateConfig(s); err == nil {
		t.Fatal("anonymized dnscrypt requires one explicit relay")
	}
	s.RelayName = "relay-x"
	if _, err := GenerateConfig(s); err != nil {
		t.Fatalf("anonymized with relay must generate: %v", err)
	}
}

func TestGenerateConfigRejectsHTTP3Misuse(t *testing.T) {
	s := specFixture("127.0.0.1:55331")
	s.HTTP3 = true
	if _, err := GenerateConfig(s); err == nil {
		t.Fatal("http3 allowed only for doh3 candidate")
	}
}

func TestValidateKeysRejectsUnknown(t *testing.T) {
	if err := ValidateKeys("listen_addresses = ['127.0.0.1:5300']\neviltwin = true\n"); err == nil {
		t.Fatal("unknown key must be rejected")
	}
	if err := ValidateKeys("query_log.file = '/tmp/q.log'\n"); err == nil {
		t.Fatal("privacy-prohibited key must be rejected")
	}
}

func TestDiagnosticInstanceCacheOff(t *testing.T) {
	s := specFixture("127.0.0.1:55331")
	s.Diagnostic = true
	cfg, err := GenerateConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "cache = false") {
		t.Fatal("diagnostic instance must disable cache (fresh evidence)")
	}
}

func TestCatalogSignatureAndAtomicUpdate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	payload := []byte("version|catalog-2026-08-01\nserver-a|dnscrypt|true|true|true\n")
	sig := SignaturePayload{
		PublicKey: pubB64,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}
	dir := t.TempDir()
	cat, err := AtomicUpdate(dir, payload, sig, pubB64, 16)
	if err != nil {
		t.Fatalf("signed catalog must apply: %v", err)
	}
	if cat.Version != "catalog-2026-08-01" || len(cat.Entries) != 1 {
		t.Fatal("catalog parse mismatch")
	}
	// unsigned/tampered replacement must fail and last-good must restore
	bad := []byte("version|catalog-evil\nserver-b|dnscrypt|false|false|false\n")
	badSig := SignaturePayload{PublicKey: pubB64, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bad))}
	// tamper payload after signing
	tampered := []byte("version|catalog-evil2\nserver-b|dnscrypt|false|false|false\n")
	if _, err := AtomicUpdate(dir, tampered, badSig, pubB64, 16); !errors.Is(err, ErrUnsignedCatalog) {
		t.Fatal("tampered catalog must be rejected (dns_unsigned_catalog_applied_total)")
	}
	current, err := os.ReadFile(filepath.Join(dir, "catalog.current"))
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(payload) {
		t.Fatal("rejected update must not replace current catalog")
	}
	// valid second update retains last-good, rollback restores it
	payload2 := []byte("version|catalog-2026-08-02\nserver-c|doh|true|true|false\n")
	sig2 := SignaturePayload{PublicKey: pubB64, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload2))}
	if _, err := AtomicUpdate(dir, payload2, sig2, pubB64, 16); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(dir); err != nil {
		t.Fatal(err)
	}
	current, _ = os.ReadFile(filepath.Join(dir, "catalog.current"))
	if string(current) != string(payload) {
		t.Fatal("rollback must restore last-good catalog")
	}
}

func TestCatalogRejectsForeignSigner(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	payload := []byte("version|v1\na|dnscrypt|true|true|true\n")
	sig := SignaturePayload{PublicKey: pubB64, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(otherPriv, payload))}
	if err := VerifyCatalogSignature(payload, sig, pubB64); !errors.Is(err, ErrUnsignedCatalog) {
		t.Fatal("foreign signer must be rejected")
	}
}

func TestSupervisorLifecycle(t *testing.T) {
	bin := sleepBinary(t)
	m := manifestFor(t, bin)
	dir := t.TempDir()
	workDir := filepath.Join(dir, "instance-1")
	spec := specFixture("127.0.0.1:55399")
	attempts := 0
	readiness := func(ctx context.Context, listenAddr string) error {
		attempts++
		if attempts < 3 {
			return errors.New("not ready yet")
		}
		return nil
	}
	sup := NewSupervisor(m, bin, workDir, spec, readiness)
	// binary is /bin/sleep which ignores -config; spawn will fail because
	// sleep requires a numeric arg — use a wrapper script instead.
	wrapper := filepath.Join(dir, "fake-backend.sh")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sup.BinaryPath = wrapper
	sup.Manifest = manifestFor(t, wrapper)
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("supervisor start must succeed after readiness retries: %v", err)
	}
	if sup.State() != StateReady {
		t.Fatalf("state must be ready, got %s", sup.State())
	}
	if attempts < 3 {
		t.Fatal("readiness must be functional polling, not fixed sleep")
	}
	if _, err := os.Stat(filepath.Join(workDir, "dnscrypt-proxy.toml")); err != nil {
		t.Fatal("generated config must exist in workdir")
	}
	if err := sup.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sup.State() != StateRetired {
		t.Fatal("state must be retired")
	}
	if _, err := os.Stat(workDir); !os.IsNotExist(err) {
		t.Fatal("retire must remove owned temp state (dns_cleanup_incomplete_total)")
	}
}

func TestSupervisorRefusesUnverifiedBinary(t *testing.T) {
	bin := sleepBinary(t)
	m := manifestFor(t, bin)
	m.SHA256 = strings.Repeat("1", 64)
	sup := NewSupervisor(m, bin, t.TempDir(), specFixture("127.0.0.1:55398"), func(context.Context, string) error { return nil })
	if err := sup.Start(context.Background()); !errors.Is(err, ErrUnverifiedBinary) {
		t.Fatal("unverified binary must never start")
	}
	if sup.State() != StateFailed {
		t.Fatal("state must be failed")
	}
}

func TestSupervisorRestartBudget(t *testing.T) {
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "fake-backend.sh")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := manifestFor(t, wrapper)
	sup := NewSupervisor(m, wrapper, filepath.Join(dir, "inst"), specFixture("127.0.0.1:55397"), func(context.Context, string) error { return nil })
	sup.MaxRestarts = 2
	sup.BackoffBase = time.Millisecond
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	sup.NotifyCrash()
	if sup.State() != StateFailed {
		t.Fatal("crash must invalidate health immediately")
	}
	if err := sup.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sup.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sup.Restart(context.Background()); err == nil {
		t.Fatal("restart budget must be bounded")
	}
	if err := sup.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAllocateLoopbackPort(t *testing.T) {
	addr, err := AllocateLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatal("allocated listener must be loopback")
	}
}
