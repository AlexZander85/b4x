// Kernel-TUN PBR owner tests (review P2 stage в, review §6): a FAKE route
// table drives the full wiring matrix — command order, idempotency, the
// verify-failure rollback, the assert/repair cycle, teardown ownership and
// the token-exact device matching — plus the config defaults and the
// honest tunnel_mode validation.
package protonservice

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/transport/proton"
)

// fakeRouteTable records every command; "route get" answers with the
// scripted device (good=true) or a foreign one (good=false).
type fakeRouteTable struct {
	mu      sync.Mutex
	log     []string
	dev     string
	good    bool
	onWrite func(cmd string) // optional hook for extra scripted behavior
}

func (f *fakeRouteTable) run(ctx context.Context, args ...string) (string, error) {
	f.mu.Lock()
	cmd := strings.Join(args, " ")
	f.log = append(f.log, cmd)
	hook := f.onWrite
	dev, good := f.dev, f.good
	f.mu.Unlock()

	if hook != nil {
		hook(cmd)
	}
	if len(args) >= 2 && args[0] == "route" && args[1] == "get" {
		if good {
			return fmt.Sprintf("8.8.8.8 via 10.0.0.1 dev %s src 10.2.0.2", dev), nil
		}
		return "8.8.8.8 via 10.0.0.1 dev eth0 src 10.9.9.5", nil
	}
	return "", nil
}

func (f *fakeRouteTable) cmds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeRouteTable) count(prefix string) int {
	n := 0
	for _, c := range f.cmds() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func newTestTable() *fakeRouteTable {
	return &fakeRouteTable{dev: "b4proton0", good: true}
}

func newTestRouter(t *testing.T, table *fakeRouteTable) *kernelRouter {
	t.Helper()
	krn, err := newKernelRouter(kernelRouteConfig{
		Device:   "b4proton0",
		LocalV4:  "10.2.0.2",
		LocalV6:  "2a07:b944::2:2",
		Mark:     0xB4B4,
		Table:    5182,
		Priority: 15182,
		Runner:   table.run,
	})
	if err != nil {
		t.Fatal(err)
	}
	return krn
}

func TestKernelRouteSetupWiring(t *testing.T) {
	table := newTestTable()
	krn := newTestRouter(t, table)

	var events []string
	krn.cfg.OnEvent = func(name, detail string) { events = append(events, name) }

	if err := krn.Setup(context.Background()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	wantPrefixes := []string{
		"addr add 10.2.0.2/32 dev b4proton0",
		"-6 addr add 2a07:b944::2:2/128 dev b4proton0",
		"link set b4proton0 up",
		"rule add fwmark 0xb4b4/0xb4b4 lookup 5182 priority 15182",
		"-6 rule add fwmark 0xb4b4/0xb4b4 lookup 5182 priority 15182",
		"route replace default dev b4proton0 table 5182",
		"route get 8.8.8.8 fwmark 0xb4b4",
	}
	for _, want := range wantPrefixes {
		if table.count(want) == 0 {
			t.Fatalf("missing command %q in %v", want, table.cmds())
		}
	}
	if len(events) != 1 || events[0] != "proton_kernel_route_applied" {
		t.Fatalf("events = %v, want one applied", events)
	}
}

func TestKernelRouteSetupIdempotent(t *testing.T) {
	table := newTestTable()
	krn := newTestRouter(t, table)
	if err := krn.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	var events int
	krn.cfg.OnEvent = func(name, _ string) { events++ }
	if err := krn.Setup(context.Background()); err != nil {
		t.Fatalf("second setup: %v", err)
	}
	if events != 0 {
		t.Fatalf("re-setup re-emitted applied %d times", events)
	}
	if krn.countAppliedReplaced(table) < 2 {
		t.Fatal("re-setup must still re-run the idempotent route replace")
	}
}

func (k *kernelRouter) countAppliedReplaced(table *fakeRouteTable) int {
	return table.count("route replace default dev b4proton0 table 5182")
}

func TestKernelRouteVerifyFailureRollsBack(t *testing.T) {
	table := newTestTable()
	table.good = false // the marked route resolves to a foreign device
	krn := newTestRouter(t, table)

	if err := krn.Setup(context.Background()); err == nil {
		t.Fatal("setup must fail when the marked route misses our device")
	}
	rollbackRule, rollbackRoute := false, false
	for _, c := range table.cmds() {
		if strings.HasPrefix(c, "rule del fwmark 0xb4b4") {
			rollbackRule = true
		}
		if c == "route del default table 5182" {
			rollbackRoute = true
		}
		if c == "route del default" {
			t.Fatal("rollback must never delete the MAIN default route")
		}
	}
	if !rollbackRule || !rollbackRoute {
		t.Fatalf("rollback incomplete: rule=%t route=%t in %v", rollbackRule, rollbackRoute, table.cmds())
	}
}

func TestKernelRouteDeviceTokenExact(t *testing.T) {
	table := newTestTable()
	// A PREFIX-COLLIDING device name must NOT satisfy the verify (E7).
	table.dev = "b4proton01"
	table.good = true
	krn := newTestRouter(t, table)
	if err := krn.Setup(context.Background()); err == nil {
		t.Fatal("dev b4proton01 must not match dev b4proton0 (token-exact)")
	}
}

func TestKernelRouteAssertRepairs(t *testing.T) {
	table := newTestTable()
	// Simulating reality: once the repair re-pins the default route, the
	// effective marked route points back at our device.
	table.onWrite = func(cmd string) {
		if strings.HasPrefix(cmd, "route replace default dev b4proton0") {
			table.mu.Lock()
			table.good = true
			table.mu.Unlock()
		}
	}
	krn := newTestRouter(t, table)
	if err := krn.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}

	var events []string
	krn.cfg.OnEvent = func(name, _ string) { events = append(events, name) }

	table.mu.Lock()
	table.good = false // the pin was wiped by a foreign actor
	table.mu.Unlock()
	if err := krn.Assert(context.Background()); err != nil {
		t.Fatalf("assert with repair: %v", err)
	}
	if err := krn.Assert(context.Background()); err != nil {
		t.Fatalf("assert after repair: %v", err)
	}
	lost, restored := false, false
	for _, e := range events {
		switch e {
		case "proton_kernel_route_lost":
			lost = true
		case "proton_kernel_pin_restored":
			restored = true
		}
	}
	if !lost || !restored {
		t.Fatalf("assert events = %v, want lost+restored", events)
	}
	if table.count("route replace default dev b4proton0 table 5182") < 2 {
		t.Fatal("assert did not re-apply the default route")
	}
}

func TestKernelRouteTeardown(t *testing.T) {
	table := newTestTable()
	krn := newTestRouter(t, table)
	if err := krn.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(table.cmds())
	krn.Teardown(context.Background())

	delRule, delRoute := 0, 0
	for _, c := range table.cmds()[before:] {
		if strings.HasPrefix(c, "rule del fwmark 0xb4b4/0xb4b4 lookup 5182") {
			delRule++
		}
		if c == "route del default table 5182" {
			delRoute++
		}
		if c == "route del default" {
			t.Fatal("teardown must never touch the MAIN default route")
		}
	}
	if delRule == 0 || delRoute != 1 {
		t.Fatalf("teardown commands = %v (rule=%d route=%d)", table.cmds()[before:], delRule, delRoute)
	}
}

func TestKernelRouteConfigValidation(t *testing.T) {
	noop := func(ctx context.Context, args ...string) (string, error) { return "", nil }
	if _, err := newKernelRouter(kernelRouteConfig{LocalV4: "10.2.0.2", Mark: 1, Table: 2, Runner: noop}); err == nil {
		t.Fatal("empty device must be rejected")
	}
	if _, err := newKernelRouter(kernelRouteConfig{Device: "d", LocalV4: "", Mark: 1, Table: 2, Runner: noop}); err == nil {
		t.Fatal("empty v4 must be rejected")
	}
	if _, err := newKernelRouter(kernelRouteConfig{Device: "d", LocalV4: "10.2.0.2", Mark: 0, Table: 2, Runner: noop}); err == nil {
		t.Fatal("zero mark must be rejected")
	}
	if _, err := newKernelRouter(kernelRouteConfig{Device: "d", LocalV4: "10.2.0.2", Mark: 1, Table: 2}); err == nil {
		t.Fatal("nil runner must be rejected")
	}
}

// TestProtonConfigTunnelDefaults pins the PBR ID defaults: mark 0xB4B4 and
// table 5182 sit OUTSIDE the per-set auto ranges (0x100..0x7EFF / 100..249)
// and the queue bypass mark — no collision with the scoped machinery.
func TestProtonConfigTunnelDefaults(t *testing.T) {
	cfg := &config.ProtonConfig{}
	if got := cfg.EffectiveTunnelMode(); got != config.ProtonTunnelNetstack {
		t.Fatalf("default mode = %q, want netstack", got)
	}
	if got := cfg.EffectiveKernelDevice(); got != "b4proton0" {
		t.Fatalf("default device = %q", got)
	}
	if got := cfg.EffectiveRouteMark(); got != 0xB4B4 {
		t.Fatalf("default mark = 0x%x, want 0xb4b4", got)
	}
	if got := cfg.EffectiveRouteTable(); got != 5182 {
		t.Fatalf("default table = %d, want 5182", got)
	}
	if prio := 10000 + cfg.EffectiveRouteTable(); prio != 15182 {
		t.Fatalf("prio = %d, want 15182", prio)
	}
	if mark := cfg.EffectiveRouteMark(); mark >= 0x100 && mark <= 0x7EFF {
		t.Fatal("default mark collides with the per-set auto range")
	}
	cfg2 := &config.ProtonConfig{TunnelMode: "kernel", KernelDevice: "p0", RouteMark: 0x99, RouteTable: 99}
	if cfg2.EffectiveKernelDevice() != "p0" || cfg2.EffectiveRouteMark() != 0x99 || cfg2.EffectiveRouteTable() != 99 {
		t.Fatal("config overrides not honored")
	}
	if cfg2.EffectiveTunnelMode() != config.ProtonTunnelKernel {
		t.Fatal("kernel mode not honored")
	}
}

// TestBuildValidatesTunnelMode: a typo fails the build honestly.
func TestBuildValidatesTunnelMode(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.System.Proton = config.ProtonConfig{
		Enabled:      true,
		IdentityPath: filepath.Join(dir, "identity.json"),
		TunnelMode:   "kernal",
	}
	if _, err := Build(cfg, Options{Now: time.Now}); err == nil {
		t.Fatal("invalid tunnel_mode must fail Build")
	}
	cfg.System.Proton.TunnelMode = "kernel"
	if _, err := Build(cfg, Options{Now: time.Now}); err != nil {
		t.Fatalf("kernel mode build: %v", err)
	}
}

// TestKernelRouterFromRuntime pins the runtime->router assembly (device,
// identity addresses, PBR IDs from the effective config).
func TestKernelRouterFromRuntime(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.System.Proton = config.ProtonConfig{
		Enabled:      true,
		IdentityPath: filepath.Join(dir, "identity.json"),
		TunnelMode:   "kernel",
	}
	rt, err := Build(cfg, Options{Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	rt.client.Pins = mustPinsMemory(t)
	krn, err := rt.newKernelRouter("b4proton7", &proton.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	if krn.cfg.Device != "b4proton7" {
		t.Fatalf("device = %q", krn.cfg.Device)
	}
	// The identity carries no API addresses -> the Proton constants.
	if krn.cfg.LocalV4 != "10.2.0.2" {
		t.Fatalf("local v4 = %q", krn.cfg.LocalV4)
	}
	if krn.cfg.Mark != 0xB4B4 || krn.cfg.Table != 5182 || krn.cfg.Priority != 15182 {
		t.Fatalf("PBR ids = mark 0x%x table %d prio %d", krn.cfg.Mark, krn.cfg.Table, krn.cfg.Priority)
	}
	if krn.cfg.Runner == nil {
		t.Fatal("production runner must be wired")
	}
}

// TestExitProbeSkippedInKernelMode: a nil dial (kernel tunnel mode) SKIPS
// the probe honestly — event emitted, exit view untouched, no failure class.
func TestExitProbeSkippedInKernelMode(t *testing.T) {
	rt := newExitTestRuntime(t, config.ProtonLocation{Mode: "country", Country: "NL"})
	rt.runExitProbe(exitProbeNode(), exitProbeProfile(), nil, nil)
	skipped := false
	for _, ev := range rt.Status().Events {
		if ev.Name == "proton_exit_probe_failed" {
			t.Fatal("kernel mode must SKIP the probe, not fail it")
		}
		if ev.Name == "proton_exit_probe_skipped" {
			skipped = true
		}
	}
	if !skipped {
		t.Fatal("proton_exit_probe_skipped event missing")
	}
	if rt.exit.OK || rt.exit.Error != "" {
		t.Fatalf("exit view must stay empty on skip: %+v", rt.exit)
	}
	rt.mu.Lock()
	last := rt.lastFailure
	rt.mu.Unlock()
	if last != "" {
		t.Fatalf("skip must not raise a failure class: %q", last)
	}
}
