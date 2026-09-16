package awgwarpservice

// Kernel-TUN PBR tests: the wiring plans are asserted through the Run seam
// (no privileges, no kernel, no live `ip` binary). The kernel session itself
// is a field-layer concern (manual privileged gate, see transport/wg
// tun.go) — CI proves the PLANS, not the kernel state.
import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

// runRecorder captures every executed command.
type runRecorder struct {
	calls []string
	fail  func(name string, args []string) error
}

func (rec *runRecorder) run(name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	rec.calls = append(rec.calls, call)
	if rec.fail != nil {
		return rec.fail(name, args)
	}
	return nil
}

func (rec *runRecorder) joined() string { return strings.Join(rec.calls, "\n") }

func kernelTestConfig(cidrs ...string) *config.Config {
	c := config.NewConfig()
	c.System.Warp.AWG = config.WarpAWGConfig{
		Enabled: true,
		Mode:    config.WarpAWGModeKernel,
		Kernel: config.WarpAWGKernelConfig{
			FromCIDRs: cidrs,
		},
	}
	return &c
}

func TestKernelPBRUpPlan(t *testing.T) {
	rec := &runRecorder{}
	p := &KernelPBR{
		AssignedV4: "172.16.0.2",
		Table:      51820,
		Priority:   30000,
		FwMark:     51820,
		FromCIDRs:  []string{"192.168.1.0/24", "10.10.0.0/16"},
		Run:        rec.run,
	}
	if err := p.Up("awgwarp0"); err != nil {
		t.Fatalf("up: %v", err)
	}
	want := []string{
		"ip addr replace 172.16.0.2/32 dev awgwarp0",
		"ip link set dev awgwarp0 up",
		"ip route replace default dev awgwarp0 table 51820",
		// del (best effort) + add per selector, in order
		"ip rule del pref 30000 not fwmark 51820 from 192.168.1.0/24 table 51820",
		"ip rule add pref 30000 not fwmark 51820 from 192.168.1.0/24 table 51820",
		"ip rule del pref 30000 not fwmark 51820 from 10.10.0.0/16 table 51820",
		"ip rule add pref 30000 not fwmark 51820 from 10.10.0.0/16 table 51820",
	}
	if rec.joined() != strings.Join(want, "\n") {
		t.Fatalf("up plan mismatch:\n got:\n%s\nwant:\n%s", rec.joined(), strings.Join(want, "\n"))
	}
}

func TestKernelPBRUpIdempotentDelFirst(t *testing.T) {
	// A stale duplicate cannot survive an Up: every add is preceded by a
	// del of the exact spec.
	rec := &runRecorder{}
	p := &KernelPBR{
		AssignedV4: "172.16.0.2",
		Table:      51820,
		Priority:   30000,
		FwMark:     51820,
		FromCIDRs:  []string{"192.168.1.0/24"},
		Run:        rec.run,
	}
	if err := p.Up("awgwarp0"); err != nil {
		t.Fatalf("up: %v", err)
	}
	// The best-effort del failing (rule absent) must NOT abort Up.
	delFailed := false
	rec.fail = func(name string, args []string) error {
		if len(args) > 1 && args[0] == "rule" && args[1] == "del" {
			delFailed = true
			return errors.New("cannot delete: no such rule")
		}
		return nil
	}
	if err := p.Up("awgwarp0"); err != nil {
		t.Fatalf("second up must tolerate the absent-rule del: %v", err)
	}
	if !delFailed {
		t.Fatal("the del branch was not exercised")
	}
}

func TestKernelPBRUpFailsClosed(t *testing.T) {
	// A failing addr/link/route command is a STRUCTURAL rejection — never a
	// half-routed session (the session contract around KernelUp).
	rec := &runRecorder{fail: func(name string, args []string) error {
		if len(args) > 0 && args[0] == "link" {
			return errors.New("operation not permitted")
		}
		return nil
	}}
	p := &KernelPBR{
		AssignedV4: "172.16.0.2",
		Table:      51820,
		Priority:   30000,
		FwMark:     51820,
		FromCIDRs:  []string{"192.168.1.0/24"},
		Run:        rec.run,
	}
	if err := p.Up("awgwarp0"); err == nil {
		t.Fatal("link failure must abort Up")
	}
	// A failing RULE add aborts too.
	rec2 := &runRecorder{fail: func(name string, args []string) error {
		if len(args) > 1 && args[0] == "rule" && args[1] == "add" {
			return errors.New("invalid rule spec")
		}
		return nil
	}}
	p.Run = rec2.run
	if err := p.Up("awgwarp0"); err == nil {
		t.Fatal("rule add failure must abort Up")
	}
}

func TestKernelPBRUpRejectsEmptyState(t *testing.T) {
	rec := &runRecorder{}
	p := &KernelPBR{Table: 51820, Priority: 30000, FwMark: 51820, Run: rec.run}
	if err := p.Up("awgwarp0"); err == nil {
		t.Fatal("missing assigned v4 must abort Up")
	}
	p.AssignedV4 = "172.16.0.2"
	if err := p.Up(""); err == nil {
		t.Fatal("empty device must abort Up")
	}
}

func TestKernelPBRDownPlan(t *testing.T) {
	rec := &runRecorder{}
	p := &KernelPBR{
		AssignedV4: "172.16.0.2",
		Table:      51820,
		Priority:   30000,
		FwMark:     51820,
		FromCIDRs:  []string{"192.168.1.0/24", "10.10.0.0/16"},
		Run:        rec.run,
	}
	// Down is best-effort: even a failing flush is swallowed.
	p.Down("awgwarp0")
	want := []string{
		"ip rule del pref 30000 not fwmark 51820 from 192.168.1.0/24 table 51820",
		"ip rule del pref 30000 not fwmark 51820 from 10.10.0.0/16 table 51820",
		"ip route flush table 51820 dev awgwarp0",
	}
	if rec.joined() != strings.Join(want, "\n") {
		t.Fatalf("down plan mismatch:\n got:\n%s\nwant:\n%s", rec.joined(), strings.Join(want, "\n"))
	}
	// Idempotent: a second Down replays the same best-effort plan.
	rec.calls = nil
	p.Down("awgwarp0")
	if len(rec.calls) != 3 {
		t.Fatalf("second down must replay 3 commands, got %d", len(rec.calls))
	}
}

func TestBuildKernelMode(t *testing.T) {
	c := kernelTestConfig("192.168.1.0/24")
	rt, err := Build(c, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !rt.kernelMode || rt.pbr == nil {
		t.Fatal("kernel mode must arm the PBR plane")
	}
	if rt.pbr.Table != config.DefaultWarpAWGPBRTable || rt.pbr.Priority != config.DefaultWarpAWGRulePriority ||
		rt.pbr.FwMark != config.DefaultWarpAWGFwMark {
		t.Fatalf("pbr defaults: %+v", rt.pbr)
	}
	v := rt.Status()
	if v.Mode != config.WarpAWGModeKernel {
		t.Fatalf("status mode = %q, want kernel", v.Mode)
	}
	if rt.SupportsUDP() {
		t.Fatal("kernel mode has no userspace UDP carrier")
	}
	if _, err := rt.DialStream(context.Background(), mustAP("93.184.216.34:443")); !errors.Is(err, ErrKernelMode) {
		t.Fatalf("dial must refuse with ErrKernelMode, got %v", err)
	}
	if _, err := rt.DialUDP(context.Background(), mustAP("93.184.216.34:443")); !errors.Is(err, ErrKernelMode) {
		t.Fatalf("udp dial must refuse with ErrKernelMode, got %v", err)
	}
}

func TestBuildKernelModeRequiresSelectors(t *testing.T) {
	// The no-half-state rule holds at Build (the CLI path bypasses config
	// validation): kernel mode without selectors is rejected.
	c := kernelTestConfig()
	if _, err := Build(c, Options{}); err == nil {
		t.Fatal("kernel mode without from_cidrs must fail the build")
	}
	bad := kernelTestConfig("192.168.1.300/24") // not an IPv4 prefix
	if _, err := Build(bad, Options{}); err == nil {
		t.Fatal("a malformed from_cidr must fail the build")
	}
	v6 := kernelTestConfig("fd00::/8") // v6 selector — v4 only today
	if _, err := Build(v6, Options{}); err == nil {
		t.Fatal("a v6 from_cidr must fail the build (IPv4 selectors only)")
	}
}

func TestBuildNetstackModeDefault(t *testing.T) {
	// The zero-value mode is the userspace netstack plane.
	c := config.NewConfig()
	c.System.Warp.AWG.Enabled = true
	rt, err := Build(&c, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rt.kernelMode || rt.pbr != nil {
		t.Fatal("netstack mode must not arm the PBR plane")
	}
	if v := rt.Status().Mode; v != config.WarpAWGModeNetstack {
		t.Fatalf("status mode = %q, want netstack", v)
	}
}

func mustAP(s string) netip.AddrPort {
	return netip.MustParseAddrPort(s)
}
