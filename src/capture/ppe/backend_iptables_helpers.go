package ppe

import (
	"context"
	"fmt"
	"strings"
)

func (b *IPTablesBackend) list(ctx context.Context, plan FamilyPlan) ([]string, error) {
	output, err := b.run(ctx, plan, "-S")
	if err != nil {
		return nil, err
	}
	return nonEmptyLines(output), nil
}

func (b *IPTablesBackend) listChain(ctx context.Context, plan FamilyPlan, chain string) ([]string, error) {
	output, err := b.run(ctx, plan, "-S", chain)
	if err != nil {
		return nil, err
	}
	return nonEmptyLines(output), nil
}

func (b *IPTablesBackend) run(ctx context.Context, plan FamilyPlan, args ...string) (string, error) {
	base := make([]string, 0, len(args)+3)
	if plan.WaitSupported {
		base = append(base, "-w")
	}
	base = append(base, "-t", "mangle")
	base = append(base, args...)
	return b.runner.Run(ctx, plan.Binary, base...)
}

func desiredChainRules(plan FamilyPlan) ([][]string, [][]string, error) {
	var pre, fwd [][]string
	for _, line := range plan.Rules {
		args, err := splitRuleLine(line)
		if err != nil {
			return nil, nil, err
		}
		if len(args) < 2 || args[0] != "-A" {
			return nil, nil, fmt.Errorf("invalid desired rule %q", line)
		}
		switch args[1] {
		case ChainPre:
			pre = append(pre, args)
		case ChainFwd:
			fwd = append(fwd, args)
		default:
			return nil, nil, fmt.Errorf("desired rule targets unowned chain %q", args[1])
		}
	}
	return pre, fwd, nil
}

func equalRules(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.Join(a[i], "\x00") != strings.Join(b[i], "\x00") {
			return false
		}
	}
	return true
}

func nonEmptyLines(value string) []string {
	var out []string
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

func isMissingChain(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no chain/target/match") || strings.Contains(message, "chain does not exist") || strings.Contains(message, "bad rule")
}
