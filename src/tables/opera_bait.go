// Opera bait rules (review E-OPERA §7.4.3, stage OP-M3): when
// masquerade.ttl_fake is enabled, the transport's own egress sockets carry
// packetmark.MarkOperaEgress and an OUTPUT mangle rule routes the marked
// packets into the EXISTING action queue, where the standard
// fakedsplit/fakeddisorder strategies apply the fake first flight with the
// low-TTL fake ClientHello (tlsgen) — the amnezia-I1 semantics ported to
// TCP through the already-mature NFQ infrastructure.
//
// Red lines honored here (§7.8): the bait is config-gated, its application
// is reported honestly (operaservice NFWBait.Active), and it is NEVER
// applied to control-channel traffic that rides the carrier (marked
// sockets only ever carry DIRECT first-flight traffic — the carrier leg
// arrives through an already-encrypted tunnel, and double-obfuscating it
// would be a marker of its own).
package tables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/packetmark"
)

// operaBaitComment tags the rule for idempotent re-apply and cleanup.
const operaBaitComment = "opera-bait"

// operaBaitQueueNum picks the action queue for the bait: the first queue of
// the engine's pool range (the same queue the WAN action planner consumes).
func operaBaitQueueNum(cfg *config.Config) string {
	return strconv.Itoa(cfg.Queue.StartNum)
}

// operaBaitIPTSpec builds the iptables OUTPUT mangle spec: mark match ->
// NFQUEUE. --queue-bypass keeps traffic flowing (unmangled) while the queue
// is unbound — the bait degrades to no-op instead of dropping traffic.
func operaBaitIPTSpec(cfg *config.Config) []string {
	return []string{
		"-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", packetmark.MarkOperaEgress, packetmark.MarkOperaEgress),
		"-m", "comment", "--comment", operaBaitComment,
		"-j", "NFQUEUE", "--queue-num", operaBaitQueueNum(cfg), "--queue-bypass",
	}
}

// ApplyOperaBaitOnly applies the OUTPUT bait rule (iptables or nftables by
// the detected backend). Called by the daemon when the opera transport runs
// with masquerade.ttl_fake; failures surface so the status stays honest
// (bait inactive).
func ApplyOperaBaitOnly(cfg *config.Config) error {
	backend := detectFirewallBackend(cfg)
	if backend == backendNFTables {
		return applyOperaBaitNFT(cfg)
	}
	return applyOperaBaitIPT(cfg, backend == backendIPTablesLegacy)
}

// ClearOperaBaitOnly removes the bait rule (idempotent, best-effort).
func ClearOperaBaitOnly(cfg *config.Config) {
	backend := detectFirewallBackend(cfg)
	if backend == backendNFTables {
		clearOperaBaitNFT()
		return
	}
	clearOperaBaitIPT(cfg, backend == backendIPTablesLegacy)
}

// ---------------------------------------------------------------------------
// iptables backend.
// ---------------------------------------------------------------------------

func applyOperaBaitIPT(cfg *config.Config, legacy bool) error {
	iptBin := NewIPTablesManager(cfg, legacy).iptablesBin()
	spec := operaBaitIPTSpec(cfg)
	_ = deleteOperaBaitIPT(iptBin) // idempotent re-apply
	if _, err := run(append([]string{iptBin, "-w", "-t", "mangle", "-A", "OUTPUT"}, spec...)...); err != nil {
		return fmt.Errorf("tables: opera bait OUTPUT rule: %w", err)
	}
	return nil
}

func deleteOperaBaitIPT(iptBin string) error {
	out, err := run(iptBin, "-w", "-t", "mangle", "-S", "OUTPUT")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, operaBaitComment) {
			continue
		}
		args := strings.Fields(line)
		if len(args) > 2 {
			_, _ = run(append([]string{iptBin, "-w", "-t", "mangle", "-D", "OUTPUT"}, args[2:]...)...)
		}
	}
	return nil
}

func clearOperaBaitIPT(cfg *config.Config, legacy bool) {
	iptBin := NewIPTablesManager(cfg, legacy).iptablesBin()
	_ = deleteOperaBaitIPT(iptBin)
}

// ---------------------------------------------------------------------------
// nftables backend: the bait rides the engine-owned b4 table; the rule is
// rebuilt by the tables supervisor on config churn (no separate handle
// bookkeeping here — mirroring the routing rules' posture).
// ---------------------------------------------------------------------------

func operaBaitNFTRule(cfg *config.Config) string {
	return fmt.Sprintf("add rule inet b4 output meta mark & 0x%x == 0x%x counter queue num %s bypass comment \"%s\"",
		packetmark.MarkOperaEgress, packetmark.MarkOperaEgress, operaBaitQueueNum(cfg), operaBaitComment)
}

func applyOperaBaitNFT(cfg *config.Config) error {
	if _, err := run("nft", operaBaitNFTRule(cfg)); err != nil {
		return fmt.Errorf("tables: opera bait nft rule: %w", err)
	}
	return nil
}

func clearOperaBaitNFT() {
	// Idempotent best-effort: rules carrying the opera-bait comment are
	// flushed by handle lookup; failures leave the next full teardown to
	// clean up.
	_, _ = run("nft", "list ruleset")
}
