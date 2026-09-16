// Kernel-TUN PBR field layer (design §7 "kernel-TUN PBR — основной путь
// роутера"; review P2 stage в): the wiring the session's KernelUp /
// KernelDown hooks own for the AWG-WARP kernel mode. Everything here is a
// pure command PLANNER over the Run seam — production pipes iproute2
// (the `ip` binary; a field router always carries it), tests assert the
// plans with a fake runner (no privileges, no kernel).
//
// Wiring plan (Up, idempotent — every verb is a replace / del+add pair):
//
//	ip addr replace <assigned>/32 dev <device>
//	ip link set dev <device> up
//	ip route replace default dev <device> table <table>
//	per selector:
//	  ip rule del pref <p> not fwmark <mark> from <cidr> table <t>  (best effort)
//	  ip rule add pref <p> not fwmark <mark> from <cidr> table <t>
//
// The "not fwmark <mark>" guard keeps the session's own marked UDP egress on
// the main table — the classic wg-quick anti-loop. The mark is armed by the
// session itself (ListenFwMark renders as fwmark in IpcSet, the device
// SetMark's its bind socket), so the encrypted outer packets never match the
// policy selectors and cannot loop back into the TUN.
//
// Down (idempotent, called BEFORE the device disappears — the session
// teardown order pins that):
//
//	per selector: ip rule del <spec>   (best effort)
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
	// Table is the dedicated routing table (default 51820).
	Table int
	// Priority is the policy-rule priority (default 30000, below main).
	Priority int
	// FwMark is the anti-loop mark of the session's own UDP socket.
	FwMark uint32
	// FromCIDRs are the IPv4 source selectors routed through the tunnel.
	FromCIDRs []string // normalized dotted-quad prefixes

	// Run executes one `ip` subcommand. nil -> the exec runner. Tests pin a
	// recorder here; production never sets it.
	Run func(name string, args ...string) error

	// mu serializes Up/Down (the session may re-establish concurrently with
	// an operator-forced teardown).
	mu sync.Mutex
}

// run executes one command through the seam.
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

// spec renders one policy rule spec ("pref P not fwmark M from C table T").
func (p *KernelPBR) spec(cidr string) []string {
	return []string{
		"pref", strconv.Itoa(p.Priority),
		"not", "fwmark", strconv.FormatUint(uint64(p.FwMark), 10),
		"from", cidr,
		"table", strconv.Itoa(p.Table),
	}
}

// Up arms the kernel wiring for one device. Called by the session right
// after the TUN exists and before the trust gate (the raw probe path rides
// the kernel addressing). A failure is a structural rejection — the session
// never ships half-routed.
func (p *KernelPBR) Up(device string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
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
	for _, cidr := range p.FromCIDRs {
		// Best-effort del first: a stale duplicate from an unbalanced pair
		// cannot survive an Up (delete-then-add = exactly one copy).
		_ = p.run(append([]string{"rule", "del"}, p.spec(cidr)...)...)
		if err := p.run(append([]string{"rule", "add"}, p.spec(cidr)...)...); err != nil {
			return fmt.Errorf("rule %s: %w", cidr, err)
		}
	}
	return nil
}

// Down removes the policy plane while the device still exists (the session
// teardown contract). Best-effort by design: a rule already gone is success.
func (p *KernelPBR) Down(device string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if device == "" {
		return
	}
	for _, cidr := range p.FromCIDRs {
		_ = p.run(append([]string{"rule", "del"}, p.spec(cidr)...)...)
	}
	if p.Table > 0 {
		_ = p.run("route", "flush", "table", strconv.Itoa(p.Table), "dev", device)
	}
}
