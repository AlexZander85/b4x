package ppe

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type IPTablesABIsolation struct {
	Runner  Runner
	Current func() (DesiredState, bool)
}

func (i IPTablesABIsolation) BeginBypass(ctx context.Context, runID, family string, tcpSourcePort, quicSourcePort uint16) (func(context.Context) error, error) {
	if !safeRunID(runID) {
		return nil, errors.New("invalid self-test run_id")
	}
	desired, ok := i.current()
	if !ok {
		return nil, errors.New("no active PPE generation")
	}
	plan, ok := familyPlan(desired, family)
	if !ok || !plan.Enabled {
		return nil, fmt.Errorf("active PPE generation has no enabled %s plan", family)
	}
	rules := bypassRules(runID, tcpSourcePort, quicSourcePort)
	installed := make([]isolatedRule, 0, len(rules)*2)
	for _, chain := range []string{ChainPre, ChainFwd} {
		for _, args := range rules {
			full := append([]string{"-t", "mangle", "-I", chain, "1"}, args...)
			if _, err := i.run(ctx, plan, full...); err != nil {
				cleanupCtx := context.Background()
				_ = i.removeRules(cleanupCtx, plan, installed)
				return nil, fmt.Errorf("install A/B bypass in %s: %w", chain, err)
			}
			installed = append(installed, isolatedRule{chain: chain, args: append([]string(nil), args...)})
		}
	}
	var once sync.Once
	var cleanupErr error
	return func(cleanupCtx context.Context) error {
		once.Do(func() { cleanupErr = i.removeRules(cleanupCtx, plan, installed) })
		return cleanupErr
	}, nil
}

func (i IPTablesABIsolation) VerifyActive(ctx context.Context, generation string) error {
	desired, ok := i.current()
	if !ok || desired.Generation != generation {
		return errors.New("active PPE generation changed during self-test")
	}
	for _, plan := range desired.Families {
		if !plan.Enabled {
			continue
		}
		backend := NewIPTablesBackend(i.Runner)
		if err := backend.Verify(ctx, plan); err != nil {
			return fmt.Errorf("verify active %s PPE generation: %w", plan.Family, err)
		}
	}
	return nil
}

type isolatedRule struct {
	chain string
	args  []string
}

func (i IPTablesABIsolation) removeRules(ctx context.Context, plan FamilyPlan, installed []isolatedRule) error {
	var errs []error
	for index := len(installed) - 1; index >= 0; index-- {
		rule := installed[index]
		args := append([]string{"-t", "mangle", "-D", rule.chain}, rule.args...)
		if _, err := i.run(ctx, plan, args...); err != nil && !isMissingRuleError(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (i IPTablesABIsolation) run(ctx context.Context, plan FamilyPlan, args ...string) (string, error) {
	runner := i.Runner
	if runner == nil {
		runner = OSRunner{}
	}
	if plan.WaitSupported {
		args = append([]string{"-w"}, args...)
	}
	return runner.Run(ctx, plan.Binary, args...)
}

func (i IPTablesABIsolation) current() (DesiredState, bool) {
	if i.Current == nil {
		return DesiredState{}, false
	}
	return i.Current()
}

func familyPlan(desired DesiredState, family string) (FamilyPlan, bool) {
	for _, plan := range desired.Families {
		if plan.Family == family {
			return plan, true
		}
	}
	return FamilyPlan{}, false
}

func bypassRules(runID string, tcpSourcePort, quicSourcePort uint16) [][]string {
	comment := "b4:ppe:selftest:" + runID
	rules := make([][]string, 0, 2)
	if tcpSourcePort != 0 {
		rules = append(rules, []string{"-p", "tcp", "--sport", strconv.Itoa(int(tcpSourcePort)), "-m", "comment", "--comment", comment + ":tcp", "-j", "RETURN"})
	}
	if quicSourcePort != 0 {
		rules = append(rules, []string{"-p", "udp", "--sport", strconv.Itoa(int(quicSourcePort)), "-m", "comment", "--comment", comment + ":quic", "-j", "RETURN"})
	}
	return rules
}

// safeRunID guards the A/B isolation rules against option injection: the run
// ID is embedded in an iptables comment, so only a restricted character set is
// accepted. The bound is generous because automatic runs use "auto-<64-hex
// generation>" IDs (69 chars) that must fit in the 255-byte comment space.
func safeRunID(runID string) bool {
	if len(runID) < 3 || len(runID) > 128 {
		return false
	}
	for _, char := range runID {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func isMissingRuleError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "bad rule") || strings.Contains(text, "does a matching rule exist") || strings.Contains(text, "no chain/target/match")
}
