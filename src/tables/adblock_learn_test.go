// BLK-7b verification: spec shapes, nft plan content/insert semantics and —
// where iptables binaries are available — the hard ordering gate: the learn
// jump must land ABOVE every NFQUEUE capture rule of the B4 chain.
package tables

import (
	"net"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func learnTestConfig() *config.Config {
	cfg := config.NewConfig()
	cfg.Queue.IPv4Enabled = true
	cfg.Queue.IPv6Enabled = true
	cfg.Queue.Mode = ""
	cfg.System.Tables.SkipSetup = false
	cfg.AdBlock.Enabled = true
	cfg.AdBlock.IPLearn = true
	return &cfg
}

func TestAdBlockLearnActiveGuards(t *testing.T) {
	cfg := learnTestConfig()
	if !adBlockLearnActive(cfg) {
		t.Fatal("feature-on NFQUEUE config must be active")
	}

	tun := learnTestConfig()
	tun.Queue.Mode = "tun"
	if adBlockLearnActive(tun) {
		t.Fatal("TUN mode must disable kernel learn sublayer")
	}

	skip := learnTestConfig()
	skip.System.Tables.SkipSetup = true
	if adBlockLearnActive(skip) {
		t.Fatal("SkipSetup must disable kernel learn sublayer")
	}

	off := learnTestConfig()
	off.AdBlock.IPLearn = false
	if adBlockLearnActive(off) {
		t.Fatal("ip_learn=false must deactivate the sublayer")
	}
}

func TestAdBlockLearnDropSpecsShape(t *testing.T) {
	specs := adBlockLearnDropSpecs(
		normalizeLearnPorts([]string{"443", "500-502"}),
		normalizeLearnPorts([]string{"443", "80"}),
		config.LearnedIPSetV4, config.LearnedIPSetV6, true, true)

	var sawV4TCP, sawV4UDP, sawV6TCP bool
	for _, s := range specs {
		spec := strings.Join(s, " ")
		switch {
		case strings.Contains(spec, "--match-set "+config.LearnedIPSetV4+" dst") && strings.Contains(spec, "-p tcp"):
			sawV4TCP = true
		case strings.Contains(spec, "--match-set "+config.LearnedIPSetV4+" dst") && strings.Contains(spec, "-p udp"):
			sawV4UDP = true
		case strings.Contains(spec, "--match-set "+config.LearnedIPSetV6+" dst"):
			sawV6TCP = sawV6TCP || strings.Contains(spec, "-p tcp")
		}
		if !strings.HasSuffix(spec, "-j DROP") {
			t.Fatalf("learn rule must end with DROP: %s", spec)
		}
		if !strings.Contains(spec, "multiport --dports") {
			t.Fatalf("learn rule must be dport-scoped: %s", spec)
		}
	}
	if !sawV4TCP || !sawV4UDP || !sawV6TCP {
		t.Fatalf("family/proto coverage incomplete: v4tcp=%v v4udp=%v v6tcp=%v", sawV4TCP, sawV4UDP, sawV6TCP)
	}
	if got := normalizeLearnPorts([]string{"443", "500-502"})[1]; got != "500:502" {
		t.Fatalf("range normalization drifted: %q", got)
	}
}

func TestAdBlockNFTLearnPlanInsertSemantics(t *testing.T) {
	plan := adBlockNFTLearnPlan([]string{"443"}, []string{"443"},
		config.LearnedIPSetV4, config.LearnedIPSetV6, true, true)

	jumps := 0
	for _, cmd := range plan {
		if cmd[0] == "insert" && cmd[1] == "rule" {
			jumps++
			joined := strings.Join(cmd, " ")
			if !strings.Contains(joined, nftChainName+" jump "+adblockLearnChainNFT) {
				t.Fatalf("insert must target the capture chain head: %s", joined)
			}
		}
	}
	if jumps != 1 {
		t.Fatalf("exactly one head-insert expected, got %d", jumps)
	}

	// Replay the plan onto a model capture chain to PROVE the ordering
	// property: INSERT prepends, so the jump ends above pre-existing
	// NFQUEUE actions regardless of how many rules were added before.
	modelChain := [][]string{
		{"meta mark return"},                 // guard
		{"tcp dport 443 queue num 5 bypass"}, // NFQUEUE capture
	}
	for _, cmd := range plan {
		switch {
		case cmd[0] == "add" && len(cmd) > 4 && cmd[2] == "inet" && cmd[3] == nftTableName && cmd[4] == adblockLearnChainNFT:
			// object/rule additions that do not affect capture-chain order
		case cmd[0] == "insert" && cmd[1] == "rule":
			modelChain = append([][]string{cmd}, modelChain...)
		}
	}
	jumpAt, queueAt := -1, -1
	for i, rule := range modelChain {
		joined := strings.Join(rule, " ")
		if strings.Contains(joined, "jump "+adblockLearnChainNFT) {
			jumpAt = i
		}
		if strings.Contains(joined, "queue num 5") {
			queueAt = i
		}
	}
	if jumpAt != 0 {
		t.Fatalf("jump must occupy position 0 after insert, got %d", jumpAt)
	}
	if queueAt <= jumpAt {
		t.Fatalf("capture rule must sit BELOW the jump: jump=%d queue=%d", jumpAt, queueAt)
	}

	// Drop rules live in their own chain scoped to the set + counter.
	dropFound := false
	for _, cmd := range plan {
		joined := strings.Join(cmd, " ")
		if strings.Contains(joined, adblockLearnChainNFT) && strings.Contains(joined, "@"+config.LearnedIPSetV4) &&
			strings.Contains(joined, "counter drop") {
			dropFound = true
		}
	}
	if !dropFound {
		t.Fatal("plan must contain counter drop rules against the learned set")
	}
}

func TestIPTablesManifestLearnJumpAboveNFQueue(t *testing.T) {
	cfg := learnTestConfig()
	manager := NewIPTablesManager(cfg, false)
	manifest, err := manager.buildManifest()
	if err != nil {
		t.Skipf("iptables capability unavailable for ordering gate: %v", err)
	}

	lastQueueInB4 := -1
	jumpIdx := -1
	for i, rule := range manifest.Rules {
		inB4 := rule.Chain == "B4"
		spec := strings.Join(rule.Spec, " ")
		if inB4 && strings.Contains(spec, "NFQUEUE") {
			lastQueueInB4 = i
		}
		if inB4 && rule.Action == "I" && spec == "-j "+adblockLearnChainIPT {
			jumpIdx = i
		}
	}
	if jumpIdx < 0 {
		t.Fatal("learn jump missing from manifest")
	}
	if lastQueueInB4 < 0 {
		t.Fatal("precondition failed: no NFQUEUE rules found in B4 chain")
	}
	if jumpIdx < lastQueueInB4 {
		t.Fatalf("ordering violated: apply order jump=%d must come AFTER last NFQUEUE=%d "+
			"(later -I lands higher in the chain)", jumpIdx, lastQueueInB4)
	}

	// Drop rules live inside the dedicated chain.
	drops := 0
	for _, rule := range manifest.Rules {
		if rule.Chain == adblockLearnChainIPT && strings.Contains(strings.Join(rule.Spec, " "), "DROP") {
			drops++
		}
	}
	if drops == 0 {
		t.Fatal("dedicated learn chain must carry DROP rules in manifest")
	}
}

func TestChunkIPsAndFamilySplit(t *testing.T) {
	v4ip := net.ParseIP("1.2.3.4")
	v6ip := net.ParseIP("2001:db8::1")
	v4, v6 := splitByFamily([]net.IP{v4ip, v6ip, nil})
	if len(v4) != 1 || len(v6) != 1 {
		t.Fatalf("family split drifted: v4=%d v6=%d", len(v4), len(v6))
	}

	var ips []net.IP
	for i := 0; i < 600; i++ {
		ips = append(ips, net.ParseIP("10.1.0."+string(rune('a'+i%26))))
	}
	chunks := chunkIPs(ips, learnNFTElemChunk)
	if len(chunks) != 3 || len(chunks[0]) != learnNFTElemChunk || len(chunks[2]) != 88 {
		t.Fatalf("chunking drifted: %d chunks", len(chunks))
	}
	if chunkIPs(nil, 10) != nil {
		t.Fatal("empty input must yield no chunks")
	}
}
