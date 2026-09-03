// Kernel-TUN PBR owner (review P2 stage в, design §7 "kernel-TUN PBR —
// основной путь роутера", по образцу nested/kernelroute.go): in kernel
// tunnel mode the proton WG session runs over a REAL /dev/net/tun device,
// and this module owns the kernel-side wiring that makes the device a
// scoped full-scope carrier:
//
//	address 10.2.0.2/32 (+v6) -> link up
//	  -> policy rule "fwmark <mark> lookup <table> priority <prio>"
//	  -> default route via the TUN in <table>
//	  -> VERIFY with "ip route get ... fwmark <mark>" (never exit codes)
//	  -> re-asserted on every supervisor tick
//	teardown -> rules/table entries removed, foreign state untouched
//
// The mark scope is the anti-loop AND the anti-hijack boundary BY
// CONSTRUCTION: only packets marked with the proton mark ever consult the
// proton table (the WG socket itself, the control plane and every other
// transport keep the main table), so the full-scope scope decision belongs
// to whoever sets the mark — the existing scoped-router machinery or an
// explicit owner rule. RegionTransportPolicy red line holds: nothing is
// silently routed through proton.
//
// All mutation rides the injectable RouteRunner seam; unit tests drive a
// FAKE table on any OS, production shells out to iproute2 ("ip").
package protonservice

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// RouteRunner executes one route-manipulation command and returns combined
// stdout/stderr (the nested.RouteRunner shape; production: iproute2).
type RouteRunner func(ctx context.Context, args ...string) (string, error)

// ipRouteRunner is the production RouteRunner: iproute2 with a bounded
// exec window (a wedged `ip` must not pin the session lifecycle).
func ipRouteRunner(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// kernelRouteConfig wires one PBR owner instance.
type kernelRouteConfig struct {
	// Device is the ACTUAL kernel TUN interface name (post-creation).
	Device string
	// LocalV4 / LocalV6 are the tunnel addresses to place on the device
	// (the identity's WG addresses). Empty V6 skips the v6 leg.
	LocalV4 string
	LocalV6 string
	// Mark / Table / Priority are the PBR IDs.
	Mark     uint32
	Table    int
	Priority int
	// Runner is REQUIRED.
	Runner RouteRunner
	// OnEvent receives lifecycle events (non-blocking).
	OnEvent func(name, detail string)
}

// kernelRouter owns one generation's PBR wiring.
type kernelRouter struct {
	cfg kernelRouteConfig

	mu      sync.Mutex
	applied bool
}

func newKernelRouter(cfg kernelRouteConfig) (*kernelRouter, error) {
	if cfg.Device == "" {
		return nil, fmt.Errorf("protonservice: kernel route requires the device name")
	}
	if cfg.LocalV4 == "" {
		return nil, fmt.Errorf("protonservice: kernel route requires the v4 tunnel address")
	}
	if cfg.Runner == nil {
		return nil, fmt.Errorf("protonservice: kernel route requires a RouteRunner")
	}
	if cfg.Table <= 0 || cfg.Mark == 0 {
		return nil, fmt.Errorf("protonservice: kernel route requires mark/table")
	}
	return &kernelRouter{cfg: cfg}, nil
}

func (k *kernelRouter) emit(name, detail string) {
	if k.cfg.OnEvent != nil {
		k.cfg.OnEvent(name, detail)
	}
}

func (k *kernelRouter) markStr() string  { return fmt.Sprintf("0x%x/0x%x", k.cfg.Mark, k.cfg.Mark) }
func (k *kernelRouter) tableStr() string { return fmt.Sprintf("%d", k.cfg.Table) }

// Setup performs the idempotent wiring cycle and verifies coverage. Safe to
// call repeatedly (the supervisor tick re-asserts through the same entry).
func (k *kernelRouter) Setup(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.setupLocked(ctx)
}

func (k *kernelRouter) setupLocked(ctx context.Context) error {
	dev := k.cfg.Device

	// 1. Addressing: the kernel TUN ships unconfigured; without the local
	// address the stack cannot source-route into the tunnel.
	specs := []struct {
		fam  []string
		addr string
	}{{nil, k.cfg.LocalV4 + "/32"}}
	if k.cfg.LocalV6 != "" {
		specs = append(specs, struct {
			fam  []string
			addr string
		}{[]string{"-6"}, k.cfg.LocalV6 + "/128"})
	}
	for _, spec := range specs {
		args := append([]string{}, spec.fam...)
		args = append(args, "addr", "add", spec.addr, "dev", dev)
		if out, err := k.cfg.Runner(ctx, args...); err != nil {
			// Idempotency: a re-applied generation hits EEXIST — the address
			// being already present is the success shape here.
			if !strings.Contains(out, "exists") && !strings.Contains(err.Error(), "exists") {
				return fmt.Errorf("addr add %s: %v (%s)", spec.addr, err, strings.TrimSpace(out))
			}
		}
	}
	if _, err := k.cfg.Runner(ctx, "link", "set", dev, "up"); err != nil {
		return fmt.Errorf("link up: %v", err)
	}

	// 2. Policy rule: ONLY the proton-marked packets consult our table.
	// Del-loop-then-add mirrors tables/routing.go routeEnsurePolicyRouting
	// (ip rule has no replace; a stale rule from a previous generation must
	// not duplicate).
	for _, fam := range [][]string{nil, {"-6"}} {
		delArgs := append([]string{}, fam...)
		delArgs = append(delArgs, "rule", "del", "fwmark", k.markStr(), "lookup", k.tableStr())
		for i := 0; i < 10; i++ {
			if _, err := k.cfg.Runner(ctx, delArgs...); err != nil {
				break
			}
		}
		addArgs := append([]string{}, fam...)
		addArgs = append(addArgs, "rule", "add", "fwmark", k.markStr(), "lookup", k.tableStr(),
			"priority", fmt.Sprintf("%d", k.cfg.Priority))
		if out, err := k.cfg.Runner(ctx, addArgs...); err != nil && !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("rule add (fam %v): %v (%s)", fam, err, strings.TrimSpace(out))
		}
	}

	// 3. Default route via the TUN inside OUR table (main table untouched).
	if out, err := k.cfg.Runner(ctx, "route", "replace", "default", "dev", dev, "table", k.tableStr()); err != nil {
		return fmt.Errorf("route replace default: %v (%s)", err, strings.TrimSpace(out))
	}

	// 4. Coverage verification: a marked lookup MUST resolve to our device.
	// A failed verify ROLLS OUR WIRING BACK (fail-closed, the nested
	// discipline): a half-routed generation must never survive — the rule
	// would outlive the failed session and leak the mark scope.
	if err := k.verifyLocked(ctx); err != nil {
		k.rollbackLocked(ctx)
		return err
	}
	if !k.applied {
		k.applied = true
		k.emit("proton_kernel_route_applied",
			fmt.Sprintf("dev=%s mark=%s table=%d", dev, k.markStr(), k.cfg.Table))
	}
	return nil
}

// verifyLocked reads back the EFFECTIVE marked route (the exit code alone
// proves nothing) with token-exact device matching (the E7 lesson: `dev
// b4proton0` must not false-positive on `dev b4proton01`).
func (k *kernelRouter) verifyLocked(ctx context.Context) error {
	out, err := k.cfg.Runner(ctx, "route", "get", "8.8.8.8", "fwmark", fmt.Sprintf("0x%x", k.cfg.Mark))
	if err != nil {
		return fmt.Errorf("verify: %v (%s)", err, strings.TrimSpace(out))
	}
	if !devTokenIs(strings.Fields(out), k.cfg.Device) {
		return fmt.Errorf("verify: marked route misses dev %s: %s", k.cfg.Device, strings.TrimSpace(out))
	}
	return nil
}

// rollbackLocked removes OUR rule and OUR table default (verify-failure
// cleanup; the device-local addresses die with the TUN device).
func (k *kernelRouter) rollbackLocked(ctx context.Context) {
	for _, fam := range [][]string{nil, {"-6"}} {
		delArgs := append([]string{}, fam...)
		delArgs = append(delArgs, "rule", "del", "fwmark", k.markStr(), "lookup", k.tableStr())
		for i := 0; i < 10; i++ {
			if _, err := k.cfg.Runner(ctx, delArgs...); err != nil {
				break
			}
		}
	}
	_, _ = k.cfg.Runner(ctx, "route", "del", "default", "table", k.tableStr())
}

// devTokenIs reports whether the iproute2 tokens carry `dev <device>` with
// EXACT token matching (nested/kernelroute.go canon).
func devTokenIs(tok []string, dev string) bool {
	for i := 0; i+1 < len(tok); i++ {
		if tok[i] == "dev" && tok[i+1] == dev {
			return true
		}
	}
	return false
}

// Assert re-verifies the coverage NOW and re-runs the wiring when the rule
// or route was lost (an outer recreate, a flush, a careless operator). The
// supervisor tick calls it; loss and repair are surfaced exactly once per
// episode.
func (k *kernelRouter) Assert(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.verifyLocked(ctx); err != nil {
		k.emit("proton_kernel_route_lost", err.Error())
		if serr := k.setupLocked(ctx); serr != nil {
			return serr
		}
		k.emit("proton_kernel_pin_restored", fmt.Sprintf("dev=%s", k.cfg.Device))
	}
	return nil
}

// Teardown removes OUR policy rule and OUR table default. The main table is
// never touched, foreign state is never deleted blindly; the TUN device
// itself dies with the WG session (kernel destroys it on close).
func (k *kernelRouter) Teardown(ctx context.Context) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, fam := range [][]string{nil, {"-6"}} {
		delArgs := append([]string{}, fam...)
		delArgs = append(delArgs, "rule", "del", "fwmark", k.markStr(), "lookup", k.tableStr())
		for i := 0; i < 10; i++ {
			if _, err := k.cfg.Runner(ctx, delArgs...); err != nil {
				break
			}
		}
	}
	_, _ = k.cfg.Runner(ctx, "route", "del", "default", "table", k.tableStr())
	if k.applied {
		k.applied = false
		k.emit("proton_kernel_route_teardown", fmt.Sprintf("table=%d", k.cfg.Table))
	}
}
