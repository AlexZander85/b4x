package tables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daniellavrushin/b4/capture"
)

func applyCanaryNFT(scope canaryScope, spec CanarySteeringSpec) error {
	if err := runEnsure("nft", "add", "chain", "inet", nftTableName, canaryChainNFT); err != nil {
		return fmt.Errorf("failed to create canary chain: %w", err)
	}
	if _, err := run("nft", "flush", "chain", "inet", nftTableName, canaryChainNFT); err != nil {
		return err
	}
	maskHex := fmt.Sprintf("0x%x", capture.CanaryControlMarkMask)
	inverseHex := fmt.Sprintf("0x%x", ^capture.CanaryControlMarkMask)
	flowHex := fmt.Sprintf("0x%x", spec.FlowMark)
	directHex := fmt.Sprintf("0x%x", spec.DirectMark)
	injectedHex := fmt.Sprintf("0x%x", spec.InjectedMark)
	queueTokens := strings.Fields(fmt.Sprintf("queue num %d bypass", spec.QueueStart))
	if spec.QueueThreads > 1 {
		queueTokens = strings.Fields(fmt.Sprintf("queue num %d-%d bypass", spec.QueueStart, spec.QueueStart+spec.QueueThreads-1))
	}
	add := func(args ...string) error {
		_, err := run(append([]string{"nft", "add", "rule", "inet", nftTableName, canaryChainNFT}, args...)...)
		return err
	}
	if err := add("meta", "mark", injectedHex, "accept"); err != nil {
		return err
	}
	if err := add("ct", "mark", "&", maskHex, "!=", "0", "meta", "mark", "set", "(", "meta", "mark", "&", inverseHex, ")", "|", "(", "ct", "mark", "&", maskHex, ")"); err != nil {
		return err
	}
	if err := add("meta", "mark", "&", maskHex, "==", directHex, "return"); err != nil {
		return err
	}
	if err := add(append([]string{"meta", "mark", "&", maskHex, "==", flowHex}, queueTokens...)...); err != nil {
		return err
	}
	if err := add("meta", "mark", "&", maskHex, "==", flowHex, "accept"); err != nil {
		return err
	}

	selector := canaryNFTSelector(scope, spec, maskHex, inverseHex, flowHex, true)
	if err := add(selector...); err != nil {
		return err
	}
	directSelector := canaryNFTSelector(scope, spec, maskHex, inverseHex, directHex, false)
	if err := add(directSelector...); err != nil {
		return err
	}
	if err := add("meta", "mark", "&", maskHex, "!=", "0", "ct", "mark", "set", "(", "ct", "mark", "&", inverseHex, ")", "|", "(", "meta", "mark", "&", maskHex, ")"); err != nil {
		return err
	}
	if err := add(append([]string{"meta", "mark", "&", maskHex, "==", flowHex}, queueTokens...)...); err != nil {
		return err
	}
	if err := add("meta", "mark", "&", maskHex, "==", flowHex, "accept"); err != nil {
		return err
	}
	if err := add("meta", "mark", "&", maskHex, "==", directHex, "return"); err != nil {
		return err
	}

	deleteNFTRulesContaining("prerouting", canaryNFTJumpMarker)
	deleteNFTRulesContaining(nftChainName, canaryNFTBypassMarker)
	if _, err := run("nft", "insert", "rule", "inet", nftTableName, nftChainName,
		"meta", "mark", "&", maskHex, "==", flowHex, "return", "comment", `"`+canaryNFTBypassMarker+`"`); err != nil {
		return err
	}
	_, err := run("nft", "insert", "rule", "inet", nftTableName, "prerouting", "jump", canaryChainNFT, "comment", `"`+canaryNFTJumpMarker+`"`)
	return err
}

func canaryNFTSelector(scope canaryScope, spec CanarySteeringSpec, maskHex, inverseHex, markHex string, selected bool) []string {
	args := []string{"meta", "l4proto", spec.Protocol, "ct", "state", "new", "meta", "mark", "&", maskHex, "==", "0"}
	if spec.Protocol == "tcp" {
		args = append(args, "tcp", "flags", "&", "(", "syn", "|", "ack", ")", "==", "syn")
	}
	if scope.ip.IsValid() {
		family := "ip"
		if scope.ip.Is6() {
			family = "ip6"
		}
		args = append(args, family, "saddr", scope.ip.String())
	} else if scope.mac != "" {
		args = append(args, "ether", "saddr", scope.mac)
	}
	if selected && spec.Percent < 100 {
		args = append(args, "numgen", "random", "mod", "100", "<", strconv.Itoa(int(spec.Percent)))
	}
	return append(args, "meta", "mark", "set", "(", "meta", "mark", "&", inverseHex, ")", "|", markHex)
}

func clearCanaryNFT(spec CanarySteeringSpec) {
	deleteNFTRulesContaining("prerouting", canaryNFTJumpMarker)
	deleteNFTRulesContaining(nftChainName, canaryNFTBypassMarker)
	_, _ = run("nft", "flush", "chain", "inet", nftTableName, canaryChainNFT)
	_, _ = run("nft", "delete", "chain", "inet", nftTableName, canaryChainNFT)
}

func deleteNFTRulesContaining(chain, marker string) {
	out, err := run("nft", "-a", "list", "chain", "inet", nftTableName, chain)
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, marker) {
			continue
		}
		idx := strings.Index(line, "# handle ")
		if idx < 0 {
			continue
		}
		handle := strings.TrimSpace(line[idx+len("# handle "):])
		if handle != "" {
			_, _ = run("nft", "delete", "rule", "inet", nftTableName, chain, "handle", handle)
		}
	}
}
