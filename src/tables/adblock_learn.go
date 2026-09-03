// BLK-7 (addendum §BLK-8): kernel materialization of learned ad-block IPs.
//
// Owns the b4_adblock_learn(+6) set pair and their drop rules. The drop rule
// lives in a dedicated chain jumped to from the TOP of the capture chain
// (iptables -I / nft insert-rule prepend), which places it BEFORE every
// NFQUEUE capture rule: packets destined to a learned IP die in-kernel and
// never reach the userspace queue. All installs are idempotent and fail-open:
// an application error degrades to "no kernel acceleration" (log + counter
// through the adblock layer) while the SNI decision layer keeps working.
//
// Ordering guarantee discipline: this file's ensure runs at the tail of
// tables.AddRules (and therefore behind every TablesRefreshFunc rebuild), and
// the adblock worker additionally reasserts on a cadence and on demand
// (z2k#6). Nothing here ever touches global offload_policy.
package tables

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/daniellavrushin/b4/adblock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

const (
	// adblockLearnChainIPT/NFT are the dedicated learn chains; the single
	// jump from the capture chain keeps install/removal trivial and the
	// position deterministic (top).
	adblockLearnChainIPT = "B4_ADBLOCK"
	adblockLearnChainNFT = "b4_adblock_chain"
	learnPortChunk       = 15
	learnNFTElemChunk    = 256
)

// adBlockLearnActive reports whether the kernel sublayer may be installed
// right now (NFQUEUE mode, tables setup allowed, feature enabled).
func adBlockLearnActive(cfg *config.Config) bool {
	if cfg == nil || cfg.System.Tables.SkipSetup || cfg.Queue.Mode == "tun" {
		return false
	}
	if !cfg.AdBlock.Enabled || !cfg.AdBlock.IPLearn {
		return false
	}
	return cfg.Queue.IPv4Enabled || cfg.Queue.IPv6Enabled
}

func learnSetNames(cfg *config.Config) (v4, v6 string) {
	return config.LearnedIPSetV4, config.LearnedIPSetV6
}

func normalizeLearnPorts(ports []string) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, strings.ReplaceAll(p, "-", ":"))
	}
	return out
}

// adBlockLearnJumpSpec is the single head-of-B4 jump (iptables).
func adBlockLearnJumpSpec() []string {
	return []string{"-j", adblockLearnChainIPT}
}

// adBlockLearnDropSpecs builds the scoped DROP rules living inside the
// dedicated chain: dport-scoped to the configured service ports so unrelated
// traffic sharing a (guarded) learned IP keeps flowing.
func adBlockLearnDropSpecs(tcpPorts, udpPorts []string, setV4, setV6 string, ipv4, ipv6 bool) [][]string {
	var specs [][]string
	emit := func(proto string, ports []string, setName string) {
		for _, chunk := range chunkPorts(ports, learnPortChunk) {
			spec := []string{"-p", proto, "-m", "multiport", "--dports", strings.Join(chunk, ","),
				"-m", "set", "--match-set", setName, "dst", "-j", "DROP"}
			specs = append(specs, spec)
		}
	}
	if ipv4 {
		emit("tcp", tcpPorts, setV4)
		emit("udp", udpPorts, setV4)
	}
	if ipv6 {
		emit("tcp", tcpPorts, setV6)
		emit("udp", udpPorts, setV6)
	}
	return specs
}

// adBlockNFTLearnPlan renders the ordered nft argument slices for the learn
// sublayer. Pure function; unit-tested for content and ordering semantics
// (the jump is an INSERT = prepend, everything else appends).
func adBlockNFTLearnPlan(tcpPorts, udpPorts []string, setV4, setV6 string, ipv4, ipv6 bool) [][]string {
	var plan [][]string
	mkSet := func(name, addrType string) []string {
		return []string{"add", "set", "inet", nftTableName, name,
			"{", "type", addrType, ";", "flags", "timeout", ";", "}"}
	}
	if ipv4 {
		plan = append(plan, mkSet(setV4, "ipv4_addr"))
	}
	if ipv6 {
		plan = append(plan, mkSet(setV6, "ipv6_addr"))
	}
	plan = append(plan, []string{"add", "chain", "inet", nftTableName, adblockLearnChainNFT})

	dropRule := func(v6 bool, proto, portsExpr, setName string) []string {
		fam, key := "ipv4", "ip"
		if v6 {
			fam, key = "ipv6", "ip6"
		}
		return []string{"add", "rule", "inet", nftTableName, adblockLearnChainNFT,
			"meta", "nfproto", fam, key, "daddr", "@" + setName,
			proto, "dport", portsExpr, "counter", "drop"}
	}
	portExpr := func(ports []string) string {
		if len(ports) == 0 {
			return ""
		}
		if len(ports) == 1 {
			return ports[0]
		}
		return "{ " + strings.Join(ports, ", ") + " }"
	}
	emitFamily := func(v6 bool, setName string) {
		if e := portExpr(tcpPorts); e != "" {
			plan = append(plan, dropRule(v6, "tcp", e, setName))
		}
		if e := portExpr(udpPorts); e != "" {
			plan = append(plan, dropRule(v6, "udp", e, setName))
		}
	}
	if ipv4 {
		emitFamily(false, setV4)
	}
	if ipv6 {
		emitFamily(true, setV6)
	}

	// INSERT prepends: lands above every existing rule of the capture chain,
	// i.e. BEFORE the first NFQUEUE queue action regardless of rebuild order.
	plan = append(plan, []string{"insert", "rule", "inet", nftTableName, nftChainName,
		"jump", adblockLearnChainNFT})
	return plan
}

// ensureAdBlockLearnRulesTail is called at the tail of tables.AddRules (all
// backends) so every full rebuild reinstalls the sublayer in correct order.
func ensureAdBlockLearnRulesTail(cfg *config.Config) {
	if !adBlockLearnActive(cfg) {
		return
	}
	if err := EnsureAdBlockLearnRules(cfg); err != nil {
		log.Warnf("adblock: ip_learn rules not installed (fail-open; SNI layer unaffected): %v", err)
		return
	}
	// The rebuild wiped kernel elements along with the rules; ask the learn
	// worker to re-apply live entries immediately instead of waiting a tick.
	adblock.RequestReassert()
}

// EnsureAdBlockLearnRules idempotently installs set + chain + jump + drop
// rules for the currently detected backend.
func EnsureAdBlockLearnRules(cfg *config.Config) error {
	if !adBlockLearnActive(cfg) {
		return nil
	}
	setV4, setV6 := learnSetNames(cfg)
	tcpPorts := normalizeLearnPorts(cfg.CollectTCPPorts())
	udpPorts := normalizeLearnPorts(cfg.CollectUDPPorts())

	if DetectBackend(cfg) == backendNFTables {
		return ensureLearnNFT(cfg, tcpPorts, udpPorts, setV4, setV6)
	}
	return ensureLearnIPT(cfg, tcpPorts, udpPorts, setV4, setV6)
}

// ClearAdBlockLearnRules removes every kernel trace of the sublayer
// (disable path / explicit teardown).
func ClearAdBlockLearnRules(cfg *config.Config) {
	if cfg == nil || cfg.System.Tables.SkipSetup || cfg.Queue.Mode == "tun" {
		return
	}
	setV4, setV6 := learnSetNames(cfg)
	if DetectBackend(cfg) == backendNFTables {
		clearLearnNFT(setV4, setV6)
		return
	}
	clearLearnIPT(cfg, setV4, setV6)
}

// ---- iptables/ipset backend ----

func ensureLearnIPT(cfg *config.Config, tcpPorts, udpPorts []string, setV4, setV6 string) error {
	im := NewIPTablesManager(cfg, DetectBackend(cfg) == backendIPTablesLegacy)
	ipts := adblockLearnBinaries(cfg, im)
	if len(ipts) == 0 {
		return fmt.Errorf("no iptables binaries for enabled families")
	}
	if err := ensureLearnIPSets(setV4, setV6, cfg.Queue.IPv4Enabled, cfg.Queue.IPv6Enabled); err != nil {
		return err
	}

	jump := adBlockLearnJumpSpec()
	for _, bin := range ipts {
		if err := runEnsure(bin, "-w", "-t", "mangle", "-N", adblockLearnChainIPT); err != nil {
			return fmt.Errorf("create %s: %w", adblockLearnChainIPT, err)
		}
		v6Family := strings.HasPrefix(bin, "ip6")
		if !im.existsRule(bin, "mangle", "B4", jump) {
			insert := append([]string{bin, "-w", "-t", "mangle", "-I", "B4"}, jump...)
			if _, err := run(insert...); err != nil {
				return fmt.Errorf("insert learn jump into B4: %w", err)
			}
		}
		for _, spec := range adBlockLearnDropSpecs(tcpPorts, udpPorts, setV4, setV6, !v6Family, v6Family) {
			if im.existsRule(bin, "mangle", adblockLearnChainIPT, spec) {
				continue
			}
			appendArgs := append([]string{bin, "-w", "-t", "mangle", "-A", adblockLearnChainIPT}, spec...)
			if _, err := run(appendArgs...); err != nil {
				return fmt.Errorf("install learn drop rule: %w", err)
			}
		}
	}
	return nil
}

// adblockLearnBinaries mirrors buildManifest family selection.
func adblockLearnBinaries(cfg *config.Config, im *IPTablesManager) []string {
	var out []string
	if cfg.Queue.IPv4Enabled && hasBinary(im.iptablesBin()) {
		out = append(out, im.iptablesBin())
	}
	if cfg.Queue.IPv6Enabled && hasBinary(im.ip6tablesBin()) {
		out = append(out, im.ip6tablesBin())
	}
	return out
}

func ensureLearnIPSets(setV4, setV6 string, ipv4, ipv6 bool) error {
	if !hasBinary("ipset") {
		return fmt.Errorf("ipset binary not found")
	}
	create := func(name, family string) error {
		_, err := run("ipset", "create", name, "hash:ip", "family", family, "timeout", "-exist")
		if err != nil {
			return fmt.Errorf("create ipset %s: %w", name, err)
		}
		return nil
	}
	if ipv4 {
		if err := create(setV4, "inet"); err != nil {
			return err
		}
	}
	if ipv6 {
		if err := create(setV6, "inet6"); err != nil {
			return err
		}
	}
	return nil
}

func clearLearnIPT(cfg *config.Config, setV4, setV6 string) {
	im := NewIPTablesManager(cfg, DetectBackend(cfg) == backendIPTablesLegacy)
	for _, bin := range adblockLearnBinaries(cfg, im) {
		im.delAll(bin, "mangle", "B4", adBlockLearnJumpSpec())
		if im.existsChain(bin, "mangle", adblockLearnChainIPT) {
			_, _ = run(bin, "-w", "-t", "mangle", "-F", adblockLearnChainIPT)
			_, _ = run(bin, "-w", "-t", "mangle", "-X", adblockLearnChainIPT)
		}
	}
	destroyLearnIPSets(setV4, setV6)
}

func destroyLearnIPSets(setV4, setV6 string) {
	if !hasBinary("ipset") {
		return
	}
	for _, name := range []string{setV4, setV6} {
		_, _ = run("ipset", "destroy", name)
	}
}

// ---- nftables backend ----

func ensureLearnNFT(cfg *config.Config, tcpPorts, udpPorts []string, setV4, setV6 string) error {
	nm := NewNFTablesManager(cfg)
	if !hasBinary("nft") {
		return fmt.Errorf("nft binary not found")
	}
	if err := nm.createTable(); err != nil {
		return err
	}
	ipv4, ipv6 := cfg.Queue.IPv4Enabled, cfg.Queue.IPv6Enabled
	plan := adBlockNFTLearnPlan(tcpPorts, udpPorts, setV4, setV6, ipv4, ipv6)
	for _, cmd := range plan {
		if err := runEnsure(append([]string{"nft"}, cmd...)...); err != nil {
			// Idempotent re-run tolerates pre-existing objects.
			if !strings.Contains(err.Error(), "exists") {
				return err
			}
		}
	}
	return nil
}

func clearLearnNFT(setV4, setV6 string) {
	if !hasBinary("nft") {
		return
	}
	// Delete the jump rule(s) from the capture chain by handle.
	out, err := run("nft", "-a", "list", "chain", "inet", nftTableName, nftChainName)
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "jump "+adblockLearnChainNFT) {
				continue
			}
			if idx := strings.LastIndexByte(strings.TrimSpace(line), '#'); idx >= 0 {
				handle := strings.TrimSpace(line[idx+1:])
				_, _ = run("nft", "delete", "rule", "inet", nftTableName, nftChainName, "handle", handle)
			}
		}
	}
	_, _ = run("nft", "flush", "chain", "inet", nftTableName, adblockLearnChainNFT)
	_, _ = run("nft", "delete", "chain", "inet", nftTableName, adblockLearnChainNFT)
	for _, name := range []string{setV4, setV6} {
		_, _ = run("nft", "delete", "set", "inet", nftTableName, name)
	}
}

// AdBlockLearnApplier implements the adblock.LearnApplier contract against
// the detected firewall backend. Bound once in main.go with a config source;
// every call resolves the CURRENT config so mid-flight changes take effect
// without re-binding.
type AdBlockLearnApplier struct {
	src func() *config.Config
}

// NewAdBlockLearnApplier binds the backend to a live config source.
func NewAdBlockLearnApplier(src func() *config.Config) *AdBlockLearnApplier {
	return &AdBlockLearnApplier{src: src}
}

func (a *AdBlockLearnApplier) current() *config.Config {
	if a == nil || a.src == nil {
		return nil
	}
	return a.src()
}

// EnsureRules implements adblock.LearnApplier.
func (a *AdBlockLearnApplier) EnsureRules() error {
	cfg := a.current()
	if cfg == nil {
		return fmt.Errorf("adblock learn: no config")
	}
	return EnsureAdBlockLearnRules(cfg)
}

// AddIPs implements adblock.LearnApplier: batched membership add with a
// fresh timeout per entry (re-adding extends kernel lifetime).
func (a *AdBlockLearnApplier) AddIPs(ips []net.IP, ttlSec int) error {
	cfg := a.current()
	if cfg == nil || len(ips) == 0 || ttlSec <= 0 {
		return nil
	}
	v4, v6 := splitByFamily(ips)
	var firstErr error
	if DetectBackend(cfg) == backendNFTables {
		for _, fam := range []struct {
			set string
			ips []net.IP
		}{
			{config.LearnedIPSetV4, v4}, {config.LearnedIPSetV6, v6},
		} {
			if len(fam.ips) == 0 {
				continue
			}
			for _, chunk := range chunkIPs(fam.ips, learnNFTElemChunk) {
				elems := make([]string, 0, len(chunk))
				for _, ip := range chunk {
					elems = append(elems, fmt.Sprintf("%s timeout %ds", ip.String(), ttlSec))
				}
				if _, err := run("nft", "add", "element", "inet", nftTableName, fam.set,
					"{", strings.Join(elems, ", "), "}"); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
		return firstErr
	}
	if !hasBinary("ipset") {
		return fmt.Errorf("ipset binary not found")
	}
	batches := map[string][]net.IP{config.LearnedIPSetV4: v4, config.LearnedIPSetV6: v6}
	for setName, list := range batches {
		if len(list) == 0 {
			continue
		}
		var sb strings.Builder
		for _, ip := range list {
			fmt.Fprintf(&sb, "add %s %s timeout %d\n", setName, ip.String(), ttlSec)
		}
		cmd := exec.Command("ipset", "restore", "-exist")
		cmd.Stdin = strings.NewReader(sb.String())
		if out, err := cmd.CombinedOutput(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("ipset restore add %s: %w (%s)", setName, err, strings.TrimSpace(string(out)))
		}
	}
	return firstErr
}

// RemoveIPs implements adblock.LearnApplier. Best-effort by design: deleting
// an entry that already vanished from the kernel (external flush, timeout,
// table rebuild) is normal drift, not a failure — misses are logged at trace
// level so the caller's table_apply_fail counter stays meaningful.
func (a *AdBlockLearnApplier) RemoveIPs(ips []net.IP) error {
	cfg := a.current()
	if cfg == nil || len(ips) == 0 {
		return nil
	}
	v4, v6 := splitByFamily(ips)
	if DetectBackend(cfg) == backendNFTables {
		for _, fam := range []struct {
			set string
			ips []net.IP
		}{
			{config.LearnedIPSetV4, v4}, {config.LearnedIPSetV6, v6},
		} {
			for _, chunk := range chunkIPs(fam.ips, learnNFTElemChunk) {
				elems := make([]string, 0, len(chunk))
				for _, ip := range chunk {
					elems = append(elems, ip.String())
				}
				if _, err := run("nft", "delete", "element", "inet", nftTableName, fam.set,
					"{", strings.Join(elems, ", "), "}"); err != nil {
					log.Tracef("adblock learn: nft delete element %s: %v", fam.set, err)
				}
			}
		}
		return nil
	}
	if !hasBinary("ipset") {
		return nil
	}
	for _, fam := range []struct {
		set string
		ips []net.IP
	}{
		{config.LearnedIPSetV4, v4}, {config.LearnedIPSetV6, v6},
	} {
		for _, ip := range fam.ips {
			if _, err := run("ipset", "del", fam.set, ip.String()); err != nil {
				log.Tracef("adblock learn: ipset del %s %s: %v", fam.set, ip.String(), err)
			}
		}
	}
	return nil
}

// Flush implements adblock.LearnApplier.
func (a *AdBlockLearnApplier) Flush() error {
	cfg := a.current()
	if cfg == nil {
		return nil
	}
	setV4, setV6 := learnSetNames(cfg)
	if DetectBackend(cfg) == backendNFTables {
		if !hasBinary("nft") {
			return nil
		}
		var firstErr error
		for _, name := range []string{setV4, setV6} {
			if _, err := run("nft", "flush", "set", "inet", nftTableName, name); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	if !hasBinary("ipset") {
		return nil
	}
	var firstErr error
	for _, name := range []string{setV4, setV6} {
		if out, err := run("ipset", "flush", name); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("ipset flush %s: %w (%s)", name, err, strings.TrimSpace(out))
		}
	}
	return firstErr
}

// TearDown removes rules AND sets — the full-disable footprint wipe.
func (a *AdBlockLearnApplier) TearDown() error {
	cfg := a.current()
	if cfg == nil {
		return nil
	}
	ClearAdBlockLearnRules(cfg)
	return nil
}

func splitByFamily(ips []net.IP) (v4, v6 []net.IP) {
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return v4, v6
}

func chunkIPs(ips []net.IP, size int) [][]net.IP {
	if len(ips) <= size {
		if len(ips) == 0 {
			return nil
		}
		return [][]net.IP{ips}
	}
	var chunks [][]net.IP
	for i := 0; i < len(ips); i += size {
		end := i + size
		if end > len(ips) {
			end = len(ips)
		}
		chunks = append(chunks, ips[i:end])
	}
	return chunks
}
