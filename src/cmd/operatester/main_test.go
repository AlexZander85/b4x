package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/operaservice"
	opera "github.com/daniellavrushin/b4/transport/opera"
)

// harness wires the CLI deps to a loopback-only lite stand and captures
// stdout/stderr for assertions.
type harness struct {
	deps *deps
	out  *bytes.Buffer
	errb *bytes.Buffer
}

func newHarness(t *testing.T, stand *liteStand) *harness {
	t.Helper()
	h := &harness{
		out:  &bytes.Buffer{},
		errb: &bytes.Buffer{},
	}
	h.deps = &deps{
		stdout: h.out,
		stderr: h.errb,
		stdin:  strings.NewReader(""),
		newRuntime: func(cfg *config.Config) (*operaservice.Runtime, error) {
			client := newLiteClient(t, stand.srv.URL, cfg.System.Opera.IdentityPath)
			return operaservice.Build(cfg, operaservice.Options{Client: client})
		},
		signals: func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		},
	}
	return h
}

func (h *harness) exec(args ...string) int {
	h.out.Reset()
	h.errb.Reset()
	return run(args, h.deps)
}

func writeTestConfig(t *testing.T, identityPath, region string) string {
	t.Helper()
	raw := map[string]any{"system": map[string]any{"opera": map[string]any{
		"enabled":       true,
		"identity_path": identityPath,
		"region":        region,
	}}}
	blob, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal test config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "operatester.json")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return path
}

func TestUsageExitCodes(t *testing.T) {
	h := newHarness(t, newLiteStand(t))
	if code := h.exec(); code != exitUsage {
		t.Fatalf("no args: code=%d want %d", code, exitUsage)
	}
	if code := h.exec("help"); code != exitOK {
		t.Fatalf("help: code=%d want %d", code, exitOK)
	}
	if code := h.exec("bogus"); code != exitUsage {
		t.Fatalf("bogus: code=%d want %d", code, exitUsage)
	}
	// relay without --target is a usage error and must not touch the network.
	if code := h.exec("relay"); code != exitUsage {
		t.Fatalf("relay no target: code=%d want %d", code, exitUsage)
	}
	if !strings.Contains(h.errb.String(), "usage") && !strings.Contains(h.errb.String(), "--target") {
		t.Fatalf("relay usage error not surfaced: %q", h.errb.String())
	}
}

func TestRegisterHappyWritesSlot(t *testing.T) {
	stand := newLiteStand(t)
	h := newHarness(t, stand)
	slot := filepath.Join(t.TempDir(), "identity.json")
	cfgPath := writeTestConfig(t, slot, "EU")

	if code := h.exec("register", "--config", cfgPath); code != exitOK {
		t.Fatalf("register code=%d stderr=%s", code, h.errb.String())
	}
	id, err := (&opera.IdentityStore{Path: slot}).Load()
	if err != nil {
		t.Fatalf("slot load: %v", err)
	}
	if id.Format != 1 {
		t.Fatalf("format=%d want 1", id.Format)
	}
	if id.DeviceID == "" || id.DevicePassword == "" {
		t.Fatalf("identity incomplete: %+v", id.Redacted())
	}
	fi, err := os.Stat(slot)
	if err != nil {
		t.Fatalf("stat slot: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("slot perm=%04o want 0600", perm)
	}
	if n := stand.countPath("/v4/register_device"); n != 1 {
		t.Fatalf("register_device calls=%d want 1", n)
	}
	if !strings.Contains(h.out.String(), "[redacted]") {
		t.Fatalf("register output must use Redacted identity: %s", h.out.String())
	}
	if !strings.Contains(h.out.String(), `"Listening": false`) {
		t.Fatalf("fresh bootstrap must report listening=false: %s", h.out.String())
	}
}

func TestRegisterRefusedClassified(t *testing.T) {
	stand := newLiteStand(t)
	stand.setMode(liteRefuse)
	h := newHarness(t, stand)
	slot := filepath.Join(t.TempDir(), "identity.json")
	cfgPath := writeTestConfig(t, slot, "EU")

	if code := h.exec("register", "--config", cfgPath); code != exitFail {
		t.Fatalf("refused register code=%d want %d (stderr=%s)", code, exitFail, h.errb.String())
	}
	if _, err := os.Stat(slot); err == nil {
		t.Fatal("refused register must not persist an identity slot")
	}
}

func TestRegisterThrottledClassified(t *testing.T) {
	stand := newLiteStand(t)
	stand.setMode(liteThrottle)
	h := newHarness(t, stand)
	slot := filepath.Join(t.TempDir(), "identity.json")
	cfgPath := writeTestConfig(t, slot, "EU")

	if code := h.exec("register", "--config", cfgPath); code != exitFail {
		t.Fatalf("throttled register code=%d want %d", code, exitFail)
	}
}

// TestStatusAdoptDiscipline: two status runs may not re-register the device
// (registration <= 1/boot) and must not move CreatedAt.
func TestStatusAdoptDiscipline(t *testing.T) {
	stand := newLiteStand(t)
	h := newHarness(t, stand)
	slot := filepath.Join(t.TempDir(), "identity.json")
	cfgPath := writeTestConfig(t, slot, "EU")

	if code := h.exec("register", "--config", cfgPath); code != exitOK {
		t.Fatalf("register code=%d stderr=%s", code, h.errb.String())
	}
	first, err := (&opera.IdentityStore{Path: slot}).Load()
	if err != nil {
		t.Fatalf("slot load: %v", err)
	}
	regBefore := stand.countPath("/v4/register_device")

	for i := 0; i < 2; i++ {
		if code := h.exec("status", "--config", cfgPath); code != exitOK {
			t.Fatalf("status run %d code=%d stderr=%s", i, code, h.errb.String())
		}
		got, lerr := (&opera.IdentityStore{Path: slot}).Load()
		if lerr != nil {
			t.Fatalf("slot load after status %d: %v", i, lerr)
		}
		if !got.CreatedAt.Equal(first.CreatedAt) {
			t.Fatalf("status %d changed CreatedAt: %v -> %v", i, first.CreatedAt, got.CreatedAt)
		}
	}
	if got := stand.countPath("/v4/register_device"); got != regBefore {
		t.Fatalf("status re-registered device: %d -> %d", regBefore, got)
	}
	if !strings.Contains(h.out.String(), `"mode": "0600"`) {
		t.Fatalf("status must report slot mode: %s", h.out.String())
	}
}

// TestRegionSwitchKeepsDevice: SetRegion discovers the new region and never
// re-registers the device.
func TestRegionSwitchKeepsDevice(t *testing.T) {
	stand := newLiteStand(t)
	h := newHarness(t, stand)
	slot := filepath.Join(t.TempDir(), "identity.json")
	cfgPath := writeTestConfig(t, slot, "EU")

	if code := h.exec("register", "--config", cfgPath); code != exitOK {
		t.Fatalf("register code=%d stderr=%s", code, h.errb.String())
	}
	regBefore := stand.countPath("/v4/register_device")
	if code := h.exec("region", "AS", "--config", cfgPath); code != exitOK {
		t.Fatalf("region AS code=%d stderr=%s", code, h.errb.String())
	}
	if n := stand.countDiscoverRegion("AS"); n == 0 {
		t.Fatal("no AS discover issued")
	}
	if n := stand.countPath("/v4/register_device"); n != regBefore {
		t.Fatalf("region switch re-registered device: %d -> %d", regBefore, n)
	}
	if !strings.Contains(h.out.String(), `"identity_unchanged": true`) {
		t.Fatalf("region output must confirm identity unchanged: %s", h.out.String())
	}
	if code := h.exec("region", "RU", "--config", cfgPath); code != exitUsage {
		t.Fatalf("RU region must be a usage error, code=%d", code)
	}
}

// TestUDPProbeFailClosed: the TCP-only carrier must refuse native UDP.
func TestUDPProbeFailClosed(t *testing.T) {
	stand := newLiteStand(t)
	h := newHarness(t, stand)
	cfgPath := writeTestConfig(t, filepath.Join(t.TempDir(), "identity.json"), "EU")

	if code := h.exec("udp-probe", "--config", cfgPath); code != exitOK {
		t.Fatalf("udp-probe code=%d want %d (stderr=%s)", code, exitOK, h.errb.String())
	}
	out := h.out.String()
	if !strings.Contains(out, `"fail_closed": true`) || !strings.Contains(out, "carrier-no-udp") {
		t.Fatalf("udp-probe must report the typed fail-closed refusal: %s", out)
	}
}

// TestProbeEgressBlockedAndNoNetwork: after bootstrap the node is a real
// SurfEasy address, which the loopback-only dialer must block — proving the
// unit tests are egress-gated.
func TestProbeEgressBlockedAndNoNetwork(t *testing.T) {
	stand := newLiteStand(t)
	h := newHarness(t, stand)
	slot := filepath.Join(t.TempDir(), "identity.json")
	cfgPath := writeTestConfig(t, slot, "EU")

	if code := h.exec("register", "--config", cfgPath); code != exitOK {
		t.Fatalf("register code=%d stderr=%s", code, h.errb.String())
	}
	if code := h.exec("probe", "--config", cfgPath); code != exitFail {
		t.Fatalf("probe to real node code=%d want %d", code, exitFail)
	}
	if !strings.Contains(h.out.String(), `"ok": false`) {
		t.Fatalf("probe output must report failure: %s", h.out.String())
	}
	if !strings.Contains(h.errb.String(), "egress blocked by test") {
		t.Fatalf("probe must be blocked by the loopback-only dialer: %s", h.errb.String())
	}
}

// TestWatchStopsOnContext: watch exits cleanly when its signal context is
// already cancelled.
func TestWatchStopsOnContext(t *testing.T) {
	stand := newLiteStand(t)
	h := newHarness(t, stand)
	h.deps.signals = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	cfgPath := writeTestConfig(t, filepath.Join(t.TempDir(), "identity.json"), "EU")
	if code := h.exec("watch", "--interval", "1s", "--config", cfgPath); code != exitOK {
		t.Fatalf("watch code=%d want %d", code, exitOK)
	}
}
