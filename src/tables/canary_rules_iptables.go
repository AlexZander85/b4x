package tables

import (
	"fmt"

	"github.com/daniellavrushin/b4/capture"
)

func applyCanaryIPT(scope canaryScope, spec CanarySteeringSpec, legacy bool) error {
	loadKernelModules()
	for _, v6 := range []bool{false, true} {
		bin := canaryIPTBinary(v6, legacy)
		if !hasBinary(bin) || !scopeAppliesToFamily(scope, v6) {
			continue
		}
		_, _ = run(bin, "-w", "-t", "mangle", "-N", canaryChainIPT)
		if _, err := run(bin, "-w", "-t", "mangle", "-F", canaryChainIPT); err != nil {
			return err
		}
		maskHex := fmt.Sprintf("0x%x", capture.CanaryControlMarkMask)
		flow := fmt.Sprintf("0x%x/0x%x", spec.FlowMark, capture.CanaryControlMarkMask)
		direct := fmt.Sprintf("0x%x/0x%x", spec.DirectMark, capture.CanaryControlMarkMask)
		injected := fmt.Sprintf("0x%x/0xffffffff", spec.InjectedMark)
		zeroControl := fmt.Sprintf("0x0/0x%x", capture.CanaryControlMarkMask)
		queue := discoveryQueueAction(spec.QueueStart, spec.QueueThreads)

		commands := [][]string{
			{bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-m", "mark", "--mark", injected, "-j", "ACCEPT"},
			{bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-j", "CONNMARK", "--restore-mark", "--nfmask", maskHex, "--ctmask", maskHex},
			{bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-m", "mark", "--mark", direct, "-j", "RETURN"},
		}
		for _, command := range commands {
			if _, err := run(command...); err != nil {
				return err
			}
		}
		existing := append([]string{bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-m", "mark", "--mark", flow, "-j", "NFQUEUE"}, queue...)
		if _, err := run(existing...); err != nil {
			return err
		}
		if _, err := run(bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-m", "mark", "--mark", flow, "-j", "ACCEPT"); err != nil {
			return err
		}

		selected := canaryIPTSelector(bin, v6, scope, spec, zeroControl, true)
		if _, err := run(selected...); err != nil {
			return err
		}
		directRule := canaryIPTSelector(bin, v6, scope, spec, zeroControl, false)
		if _, err := run(directRule...); err != nil {
			return err
		}
		for _, mark := range []string{flow, direct} {
			if _, err := run(bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-m", "mark", "--mark", mark,
				"-j", "CONNMARK", "--save-mark", "--nfmask", maskHex, "--ctmask", maskHex); err != nil {
				return err
			}
		}
		selected = append([]string{bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-m", "mark", "--mark", flow, "-j", "NFQUEUE"}, queue...)
		if _, err := run(selected...); err != nil {
			return err
		}
		if _, err := run(bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-m", "mark", "--mark", flow, "-j", "ACCEPT"); err != nil {
			return err
		}
		if _, err := run(bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-m", "mark", "--mark", direct, "-j", "RETURN"); err != nil {
			return err
		}

		discoveryDelRuleLoop(bin, "B4", "-m", "mark", "--mark", flow, "-j", "RETURN")
		discoveryDelRuleLoop(bin, "B4_PREROUTING", "-m", "mark", "--mark", flow, "-j", "RETURN")
		if _, err := run(bin, "-w", "-t", "mangle", "-I", "B4", "1", "-m", "mark", "--mark", flow, "-j", "RETURN"); err != nil {
			return err
		}
		if _, err := run(bin, "-w", "-t", "mangle", "-I", "B4_PREROUTING", "1", "-m", "mark", "--mark", flow, "-j", "RETURN"); err != nil {
			return err
		}
		discoveryDelRuleLoop(bin, "PREROUTING", "-j", canaryChainIPT)
		if _, err := run(bin, "-w", "-t", "mangle", "-I", "PREROUTING", "1", "-j", canaryChainIPT); err != nil {
			return err
		}
	}
	return nil
}

func canaryIPTSelector(bin string, v6 bool, scope canaryScope, spec CanarySteeringSpec, zeroControl string, selected bool) []string {
	args := []string{bin, "-w", "-t", "mangle", "-A", canaryChainIPT, "-p", spec.Protocol, "-m", "conntrack", "--ctstate", "NEW", "-m", "mark", "--mark", zeroControl}
	if spec.Protocol == "tcp" {
		args = append(args, "--syn")
	}
	if scope.ip.IsValid() {
		args = append(args, "-s", scope.ip.String())
	} else if scope.mac != "" {
		args = append(args, "-m", "mac", "--mac-source", scope.mac)
	}
	if selected && spec.Percent < 100 {
		args = append(args, "-m", "statistic", "--mode", "random", "--probability", fmt.Sprintf("%.6f", float64(spec.Percent)/100))
	}
	mark := spec.DirectMark
	if selected {
		mark = spec.FlowMark
	}
	return append(args, "-j", "MARK", "--set-xmark", fmt.Sprintf("0x%x/0x%x", mark, capture.CanaryControlMarkMask))
}

func clearCanaryIPT(spec CanarySteeringSpec, legacy bool) {
	flow := fmt.Sprintf("0x%x/0x%x", spec.FlowMark, capture.CanaryControlMarkMask)
	for _, v6 := range []bool{false, true} {
		bin := canaryIPTBinary(v6, legacy)
		if !hasBinary(bin) {
			continue
		}
		discoveryDelRuleLoop(bin, "PREROUTING", "-j", canaryChainIPT)
		discoveryDelRuleLoop(bin, "B4", "-m", "mark", "--mark", flow, "-j", "RETURN")
		discoveryDelRuleLoop(bin, "B4_PREROUTING", "-m", "mark", "--mark", flow, "-j", "RETURN")
		_, _ = run(bin, "-w", "-t", "mangle", "-F", canaryChainIPT)
		_, _ = run(bin, "-w", "-t", "mangle", "-X", canaryChainIPT)
	}
}

func canaryIPTBinary(v6, legacy bool) string {
	if v6 {
		if legacy {
			return backendIP6TablesLegacy
		}
		return backendIP6Tables
	}
	if legacy {
		return backendIPTablesLegacy
	}
	return backendIPTables
}

func scopeAppliesToFamily(scope canaryScope, v6 bool) bool {
	if !scope.ip.IsValid() {
		return true
	}
	return scope.ip.Is6() == v6
}
