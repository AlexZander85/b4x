// Kernel-TUN PBR field layer (design §7 "kernel-TUN PBR — основной путь
// роутера"; review P2 stage в): the wiring the session's KernelUp /
// KernelDown hooks own for the AWG-WARP kernel mode. Everything here is a
// pure command PLANNER over the Run/IptRun seams — production pipes
// iproute2 (the `ip` binary) and iptables; tests assert the plans with fake
// runners (no privileges, no kernel).
//
// Wiring plan (Up, idempotent — every verb is a replace / del+add pair):
//
//	ip addr replace <assigned>/32 dev <device>
//	ip link set dev <device> up
//	ip route replace default dev <device> table <table>
//	# anti-loop: the session's own marked UDP keeps the main table
//	ip rule add pref <P-1> fwmark <mark> table main
//	# destination bypass: LAN/local traffic avoids the tunnel table
//	ip rule add pref <P-2> to <bypass> table main      (per bypass CIDR)
//	# per source selector:
//	ip rule add pref <P> from <cidr> table <table>
//	# SNAT + forwarding (the WARP edge binds the inner source to the
//	# assigned /32; the router must masquerade LAN sources)
//	iptables -t nat -A POSTROUTING -s <cidr> -o <device> -j MASQUERADE
//	iptables -I FORWARD 1 -o <device> -j ACCEPT
//
// BusyBox `ip` note (the field router): BusyBox 1.37 has NO `not fwmark`
// selector and its table ids are 8-bit. The anti-loop is therefore a
// POSITIVE fwmark lookup (marked packets hit the main table before the
// selector rule), and the default table is 200 (see
// config.DefaultWarpAWGPBRTable). The mark is armed by the session itself
// (ListenFwMark renders as fwmark in IpcSet, the device SetMark's its bind
// socket), so the encrypted outer packets never consult the selector table
// and cannot loop back into the TUN.
//
// Down (idempotent, called BEFORE the device disappears — the session
// teardown order pins that):
//
//	per selector: ip rule del <spec>   (best effort)
//	per bypass:   ip rule del <spec>   (best effort)
//	ip rule del pref <P-1> fwmark <mark> table main   (best effort)
//	iptables -D ... (best effort)
//	ip route flush table <table> dev <device>
package awgwarpservice

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// KernelPBR owns the policy-routing plane of one kernel-mode AWG-WARP
// session generation. AssignedV4 is set by the service right before each
// session build (the identity is loaded first); everything else is fixed at
// construction.
type KernelPBR struct {
	// AssignedV4 is the WG /32 assigned to the tunnel device.
	AssignedV4 string
	// Table is the dedicated routing table (default 200 — BusyBox-safe).
	Table int
	// Priority is the policy-rule priority (default 30000, below main).
	Priority int
	// FwMark is the anti-loop mark of the session's own UDP socket.
	FwMark uint32
	// FromCIDRs are the IPv4 source selectors routed through the tunnel.
	FromCIDRs []string // normalized dotted-quad prefixes
	// BypassCIDRs are destination prefixes kept on the main table (local
	// reachability before the tunnel selector).
	BypassCIDRs []string
	// SNAT masquerades selector traffic leaving the tunnel device.
	SNAT bool

	// Run executes one `ip` subcommand. nil -> the exec runner. Tests pin a
	// recorder here; production never sets it.
	Run func(name string, args ...string) error
	// IptRun executes one `iptables` subcommand. nil -> the exec runner.
	IptRun func(name string, args ...string) error

	// mu serializes Up/Down (the session may re-establish concurrently with
	// an operator-forced teardown).
	mu sync.Mutex
}

// run executes one `ip` command through the seam.
func (p *KernelPBR) run(args ...string) error {
	if p.Run != nil {
		return p.Run("ip", args...)
	}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("awgwarp pbr: ip %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// iptRun executes one `iptables` command through the seam.
func (p *KernelPBR) iptRun(args ...string) error {
	if p.IptRun != nil {
		return p.IptRun("iptables", args...)
	}
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("awgwarp pbr: iptables %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// antiLoopPref / bypassPref sit just ABOVE the selector priority so marked
// packets and local destinations never consult the tunnel table.
func (p *KernelPBR) antiLoopPref() int { return p.Priority - 1 }
func (p *KernelPBR) bypassPref() int   { return p.Priority - 2 }

// selectorSpec renders one policy rule spec ("pref P from C table T").
func (p *KernelPBR) selectorSpec(cidr string) []string {
	return []string{
		"pref", strconv.Itoa(p.Priority),
		"from", cidr,
		"table", strconv.Itoa(p.Table),
	}
}

// legacySelectorSpec is the pre-BusyBox `not fwmark` form; Down still emits
// it best-effort so an upgrade from an older build cannot leave a stale rule.
func (p *KernelPBR) legacySelectorSpec(cidr string) []string {
	return []string{
		"pref", strconv.Itoa(p.Priority),
		"not", "fwmark", strconv.FormatUint(uint64(p.FwMark), 10),
		"from", cidr,
		"table", strconv.Itoa(p.Table),
	}
}

// antiLoopSpec renders the positive-fwmark anti-loop rule.
func (p *KernelPBR) antiLoopSpec() []string {
	return []string{
		"pref", strconv.Itoa(p.antiLoopPref()),
		"fwmark", strconv.FormatUint(uint64(p.FwMark), 10),
		"table", "main",
	}
}

// bypassSpec renders one destination-bypass rule.
func (p *KernelPBR) bypassSpec(cidr string) []string {
	return []string{
		"pref", strconv.Itoa(p.bypassPref()),
		"to", cidr,
		"table", "main",
	}
}

// Up arms the kernel wiring for one device. Called by the session right
// after the TUN exists and before the trust gate (the raw probe path rides
// the kernel addressing). A failure is a structural rejection — the session
// never ships half-routed, and any partial wiring is rolled back first.
func (p *KernelPBR) Up(device string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.upLocked(device); err != nil {
		// Roll our own partial wiring back: the session contract only calls
		// KernelDown after a SUCCESSFUL Up (s.kernelDev is set then), so a
		// failed Up must not leak rules.
		p.downLocked(device)
		return err
	}
	return nil
}

func (p *KernelPBR) upLocked(device string) error {
	if device == "" {
		return fmt.Errorf("awgwarp pbr: empty device name")
	}
	if p.AssignedV4 == "" {
		return fmt.Errorf("awgwarp pbr: no assigned v4 yet (identity not loaded)")
	}
	// /32: WG assigns point-to-point addresses, the on-link route comes
	// with the address. `replace` keeps a re-establishment idempotent.
	if err := p.run("addr", "replace", p.AssignedV4+"/32", "dev", device); err != nil {
		return fmt.Errorf("addr: %w", err)
	}
	if err := p.run("link", "set", "dev", device, "up"); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	if err := p.run("route", "replace", "default", "dev", device, "table", strconv.Itoa(p.Table)); err != nil {
		return fmt.Errorf("table default: %w", err)
	}

	// Anti-loop (BusyBox-compatible): the session's own marked UDP packets
	// resolve to the main table BEFORE the selector rule. `not` is not
	// available on BusyBox ip. Best-effort del first keeps one copy.
	if p.FwMark != 0 {
		_ = p.run(append([]string{"rule", "del"}, p.antiLoopSpec()...)...)
		if err := p.run(append([]string{"rule", "add"}, p.antiLoopSpec()...)...); err != nil {
			return fmt.Errorf("anti-loop rule: %w", err)
		}
	}

	// Destination bypass: local/LAN reachability must not be swallowed by
	// the selector table (the selector would otherwise also capture the
	// source's traffic to the router, including the SSH control channel).
	for _, cidr := range p.BypassCIDRs {
		_ = p.run(append([]string{"rule", "del"}, p.bypassSpec(cidr)...)...)
		if err := p.run(append([]string{"rule", "add"}, p.bypassSpec(cidr)...)...); err != nil {
			return fmt.Errorf("bypass rule %s: %w", cidr, err)
		}
	}

	for _, cidr := range p.FromCIDRs {
		// Best-effort del first: a stale duplicate from an unbalanced pair
		// cannot survive an Up (delete-then-add = exactly one copy). The
		// legacy `not fwmark` del is a no-op on BusyBox (invalid selector)
		// and only cleans up rules installed by an older build.
		_ = p.run(append([]string{"rule", "del"}, p.legacySelectorSpec(cidr)...)...)
		_ = p.run(append([]string{"rule", "del"}, p.selectorSpec(cidr)...)...)
		if err := p.run(append([]string{"rule", "add"}, p.selectorSpec(cidr)...)...); err != nil {
			return fmt.Errorf("rule %s: %w", cidr, err)
		}
	}

	if p.SNAT {
		if err := p.upSNATLocked(device); err != nil {
			return err
		}
	}
	return nil
}

// upSNATLocked adds the masquerade and forwarding rules for the selectors.
func (p *KernelPBR) upSNATLocked(device string) error {
	for _, cidr := range p.FromCIDRs {
		_ = p.iptRun("-w", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-o", device, "-j", "MASQUERADE")
		if err := p.iptRun("-w", "-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-o", device, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("masquerade %s: %w", cidr, err)
		}
	}
	// Forwarding accept for the tunnel device (the router's FORWARD policy
	// is DROP; the reply direction is covered by the existing conntrack
	// ESTABLISHED accept). Inserted first so NDM's zone rules cannot shadow.
	_ = p.iptRun("-w", "-D", "FORWARD", "-o", device, "-j", "ACCEPT")
	if err := p.iptRun("-w", "-I", "FORWARD", "1", "-o", device, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("forward accept: %w", err)
	}
	return nil
}

// Down removes the policy plane while the device still exists (the session
// teardown contract). Best-effort by design: a rule already gone is success.
func (p *KernelPBR) Down(device string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.downLocked(device)
}

func (p *KernelPBR) downLocked(device string) {
	if device == "" {
		return
	}
	for _, cidr := range p.FromCIDRs {
		_ = p.run(append([]string{"rule", "del"}, p.selectorSpec(cidr)...)...)
		_ = p.run(append([]string{"rule", "del"}, p.legacySelectorSpec(cidr)...)...)
	}
	for _, cidr := range p.BypassCIDRs {
		_ = p.run(append([]string{"rule", "del"}, p.bypassSpec(cidr)...)...)
	}
	if p.FwMark != 0 {
		_ = p.run(append([]string{"rule", "del"}, p.antiLoopSpec()...)...)
	}
	if p.SNAT {
		for _, cidr := range p.FromCIDRs {
			_ = p.iptRun("-w", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-o", device, "-j", "MASQUERADE")
		}
		_ = p.iptRun("-w", "-D", "FORWARD", "-o", device, "-j", "ACCEPT")
	}
	if p.Table > 0 {
		_ = p.run("route", "flush", "table", strconv.Itoa(p.Table), "dev", device)
	}
}
