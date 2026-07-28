package ppe

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daniellavrushin/b4/config"
)

func compileFamily(family, mode string, capability FamilyCapability, policy string, ppeCfg config.PPEOffloadConfig, tcpPorts, udpPorts []uint16, scope []string) (FamilyPlan, error) {
	binary := capability.Binary
	if binary == "" {
		if family == "ipv6" {
			binary = "ip6tables"
		} else {
			binary = "iptables"
		}
	}
	plan := FamilyPlan{Family: family, Binary: binary}
	if mode == config.PPEFamilyOff {
		plan.Reason = "disabled by configuration"
		return plan, nil
	}
	if policy != config.OffloadPolicyExclude {
		plan.Reason = "policy does not request per-flow exclusion"
		return plan, nil
	}
	supported := capability.State == CapabilitySupported && capability.TargetRegistered && capability.ConnskipUsable && capability.MangleAvailable && capability.Prerouting && capability.Forward
	if !supported {
		if mode == config.PPEFamilyOn {
			return FamilyPlan{}, fmt.Errorf("%w: %s", ErrFamilyRequiredUnsupported, family)
		}
		plan.Reason = "capability unavailable in auto mode"
		return plan, nil
	}
	plan.Enabled = true
	plan.Rules = compileRules(ppeCfg, tcpPorts, udpPorts, scope)
	plan.RestoreScript = renderRestore(plan.Rules)
	return plan, nil
}

func compileRules(ppeCfg config.PPEOffloadConfig, tcpPorts, udpPorts []uint16, scope []string) []string {
	var rules []string
	for _, chain := range []string{ChainPre, ChainFwd} {
		if ppeCfg.TCPEnabled {
			for _, ports := range chunkPorts(tcpPorts, 15) {
				args := append([]string{"-A", chain}, scope...)
				args = append(args, "-p", "tcp", "-m", "multiport", "--dports", joinPorts(ports), "-m", "connskip", "--connskip", strconv.Itoa(ppeCfg.ConnskipPackets), "-m", "comment", "--comment", CommentTCP, "-j", "PPE")
				rules = append(rules, strings.Join(args, " "))
			}
		}
		if ppeCfg.QUICEnabled {
			for _, ports := range chunkPorts(udpPorts, 15) {
				args := append([]string{"-A", chain}, scope...)
				args = append(args, "-p", "udp", "-m", "multiport", "--dports", joinPorts(ports), "-m", "connskip", "--connskip", strconv.Itoa(ppeCfg.ConnskipPackets), "-m", "comment", "--comment", CommentQUIC, "-j", "PPE")
				rules = append(rules, strings.Join(args, " "))
			}
		}
	}
	return rules
}

func renderRestore(rules []string) string {
	lines := []string{
		"*mangle",
		":" + ChainPre + " - [0:0]",
		":" + ChainFwd + " - [0:0]",
		"-F " + ChainPre,
		"-F " + ChainFwd,
		"-A PREROUTING -m comment --comment " + CommentJumpPre + " -j " + ChainPre,
		"-A FORWARD -m comment --comment " + CommentJumpFwd + " -j " + ChainFwd,
	}
	lines = append(lines, rules...)
	lines = append(lines, "COMMIT", "")
	return strings.Join(lines, "\n")
}
