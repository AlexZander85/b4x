// fxvpn_bait.go: the Firefox VPN bait OUTPUT rule (review E-FXVPN §7.4.2,
// stage FX-M3) — the shared NFQ bait infrastructure with opera applied to
// this transport: when masquerade.preflight_fake is on, the transport's
// DIRECT egress sockets carry packetmark.MarkFxvpnEgress and this OUTPUT
// mangle rule routes the marked packets into the EXISTING action queue,
// where the standard fakedsplit/fakeddisorder strategies apply the fake
// first flight with the fake ClientHello (tlsgen) — the amnezia-I1
// semantics ported to TCP. The QUIC branch fires the UDP preflight bait on
// its own (masquerade.go); the TCP branch rides NFQUEUE.
//
// Red lines honored here (§7.8): the bait is config-gated, its application
// is reported honestly (fxvpservice bait seam), the carrier-nested leg is
// never marked (the outer tunnel already obfuscates it — §7.8.3), and the
// rule degrades to no-op while the queue is unbound (--queue-bypass).
package tables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/packetmark"
)

// fxvpnBaitComment tags the rule for idempotent re-apply and cleanup.
const fxvpnBaitComment = "fxvpn-bait"

func fxvpnBaitQueueNum(cfg *config.Config) string {
	return strconv.Itoa(cfg.Queue.StartNum)
}

// fxvpnBaitIPTSpec builds the iptables OUTPUT mangle spec: mark match ->
// NFQUEUE (same queue pool as the opera bait).
func fxvpnBaitIPTSpec(cfg *config.Config) []string {
	return []string{
		"-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", packetmark.MarkFxvpnEgress, packetmark.MarkFxvpnEgress),
		"-m", "comment", "--comment", fxvpnBaitComment,
		"-j", "NFQUEUE", "--queue-num", fxvpnBaitQueueNum(cfg), "--queue-bypass",
	}
}

// ApplyFxvpnBaitOnly applies the OUTPUT bait rule (iptables or nftables by
// the detected backend). Called by the daemon when the fxvpn transport runs
// with masquerade.preflight_fake; failures surface so the status stays
// honest (bait inactive).
func ApplyFxvpnBaitOnly(cfg *config.Config) error {
	backend := detectFirewallBackend(cfg)
	if backend == backendNFTables {
		return applyFxvpnBaitNFT(cfg)
	}
	return applyFxvpnBaitIPT(cfg, backend == backendIPTablesLegacy)
}

// ClearFxvpnBaitOnly removes the bait rule (idempotent, best-effort).
func ClearFxvpnBaitOnly(cfg *config.Config) {
	backend := detectFirewallBackend(cfg)
	if backend == backendNFTables {
		clearFxvpnBaitNFT()
		return
	}
	clearFxvpnBaitIPT(cfg, backend == backendIPTablesLegacy)
}

// ---------------------------------------------------------------------------
// iptables backend.
// ---------------------------------------------------------------------------

func applyFxvpnBaitIPT(cfg *config.Config, legacy bool) error {
	iptBin := NewIPTablesManager(cfg, legacy).iptablesBin()
	spec := fxvpnBaitIPTSpec(cfg)
	_ = deleteFxvpnBaitIPT(iptBin) // idempotent re-apply
	if _, err := run(append([]string{iptBin, "-w", "-t", "mangle", "-A", "OUTPUT"}, spec...)...); err != nil {
		return fmt.Errorf("tables: fxvpn bait OUTPUT rule: %w", err)
	}
	return nil
}

func deleteFxvpnBaitIPT(iptBin string) error {
	out, err := run(iptBin, "-w", "-t", "mangle", "-S", "OUTPUT")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, fxvpnBaitComment) {
			continue
		}
		args := strings.Fields(line)
		if len(args) > 2 {
			_, _ = run(append([]string{iptBin, "-w", "-t", "mangle", "-D", "OUTPUT"}, args[2:]...)...)
		}
	}
	return nil
}

func clearFxvpnBaitIPT(cfg *config.Config, legacy bool) {
	iptBin := NewIPTablesManager(cfg, legacy).iptablesBin()
	_ = deleteFxvpnBaitIPT(iptBin)
}

// ---------------------------------------------------------------------------
// nftables backend: rides the engine-owned b4 table like the opera bait.
// ---------------------------------------------------------------------------

func fxvpnBaitNFTRule(cfg *config.Config) string {
	return fmt.Sprintf("add rule inet b4 output meta mark & 0x%x == 0x%x counter queue num %s bypass comment \"%s\"",
		packetmark.MarkFxvpnEgress, packetmark.MarkFxvpnEgress, fxvpnBaitQueueNum(cfg), fxvpnBaitComment)
}

func applyFxvpnBaitNFT(cfg *config.Config) error {
	if _, err := run("nft", fxvpnBaitNFTRule(cfg)); err != nil {
		return fmt.Errorf("tables: fxvpn bait nft rule: %w", err)
	}
	return nil
}

func clearFxvpnBaitNFT() {
	_, _ = run("nft", "list ruleset")
}
