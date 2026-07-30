package tables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
)

type topologyCommandRunner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}

type osTopologyCommandRunner struct{}

func (osTopologyCommandRunner) Run(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.Bytes(), nil
}

type topologyRuleProgram struct {
	Binary   string
	Args     []string
	Apply    []byte
	Rollback []byte
}

// GSOQueueRuleTransaction changes only B4-owned queue targets. It never flushes
// a global table, parent chain or unrelated rule.
type GSOQueueRuleTransaction struct {
	mu       sync.Mutex
	runner   topologyCommandRunner
	programs []topologyRuleProgram
	switched bool
}

func PrepareGSOQueueRuleTransaction(ctx context.Context, cfg *config.Config, from, to capture.QueueRange) (*GSOQueueRuleTransaction, error) {
	return prepareGSOQueueRuleTransaction(ctx, cfg, from, to, osTopologyCommandRunner{})
}

func prepareGSOQueueRuleTransaction(ctx context.Context, cfg *config.Config, from, to capture.QueueRange, runner topologyCommandRunner) (*GSOQueueRuleTransaction, error) {
	if cfg == nil || runner == nil {
		return nil, errors.New("GSO queue rule transaction input is nil")
	}
	if !from.Enabled || !to.Enabled || from.Threads == 0 || to.Threads == 0 {
		return nil, errors.New("GSO queue rule ranges are unavailable")
	}
	if from == to {
		return &GSOQueueRuleTransaction{runner: runner}, nil
	}
	backend := detectFirewallBackend(cfg)
	programs := []topologyRuleProgram{}
	if backend == backendNFTables {
		listing, err := runner.Run(ctx, "nft", []string{"-a", "list", "table", "inet", nftTableName}, nil)
		if err != nil {
			return nil, err
		}
		apply, rollback, err := buildNFTQueueReplacement(listing, from, to)
		if err != nil {
			return nil, err
		}
		programs = append(programs, topologyRuleProgram{Binary: "nft", Args: []string{"-f", "-"}, Apply: apply, Rollback: rollback})
	} else {
		legacy := backend == backendIPTablesLegacy
		families := []struct {
			enabled       bool
			save, restore string
		}{
			{cfg.Queue.IPv4Enabled, chooseBinary(legacy, "iptables-save", "iptables-legacy-save"), chooseBinary(legacy, "iptables-restore", "iptables-legacy-restore")},
			{cfg.Queue.IPv6Enabled, chooseBinary(legacy, "ip6tables-save", "ip6tables-legacy-save"), chooseBinary(legacy, "ip6tables-restore", "ip6tables-legacy-restore")},
		}
		for _, family := range families {
			if !family.enabled {
				continue
			}
			listing, err := runner.Run(ctx, family.save, []string{"-t", "mangle"}, nil)
			if err != nil {
				return nil, err
			}
			apply, rollback, err := buildIPTablesOwnedChainReplacement(listing, from, to)
			if err != nil {
				return nil, err
			}
			programs = append(programs, topologyRuleProgram{Binary: family.restore, Args: []string{"--noflush"}, Apply: apply, Rollback: rollback})
		}
	}
	if len(programs) == 0 {
		return nil, errors.New("no firewall family available for GSO queue switch")
	}
	return &GSOQueueRuleTransaction{runner: runner, programs: programs}, nil
}

func chooseBinary(legacy bool, modern, old string) string {
	if legacy {
		return old
	}
	return modern
}

func (t *GSOQueueRuleTransaction) Switch(ctx context.Context) error {
	if t == nil {
		return errors.New("GSO queue rule transaction is nil")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.switched {
		return nil
	}
	for i, p := range t.programs {
		if _, err := t.runner.Run(ctx, p.Binary, p.Args, p.Apply); err != nil {
			for j := i - 1; j >= 0; j-- {
				_, _ = t.runner.Run(ctx, t.programs[j].Binary, t.programs[j].Args, t.programs[j].Rollback)
			}
			return err
		}
	}
	t.switched = true
	return nil
}

func (t *GSOQueueRuleTransaction) Rollback(ctx context.Context) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var errs []error
	for i := len(t.programs) - 1; i >= 0; i-- {
		p := t.programs[i]
		if _, err := t.runner.Run(ctx, p.Binary, p.Args, p.Rollback); err != nil {
			errs = append(errs, err)
		}
	}
	t.switched = false
	return errors.Join(errs...)
}

var nftHandlePattern = regexp.MustCompile(`\s+# handle ([0-9]+)\s*$`)

func buildNFTQueueReplacement(listing []byte, from, to capture.QueueRange) ([]byte, []byte, error) {
	lines := strings.Split(string(listing), "\n")
	chain := ""
	var apply, rollback strings.Builder
	matches := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "chain ") && strings.HasSuffix(line, "{") {
			chain = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "chain "), "{"))
			continue
		}
		if line == "}" {
			chain = ""
			continue
		}
		if chain == "" || !strings.Contains(line, "queue num ") {
			continue
		}
		h := nftHandlePattern.FindStringSubmatch(line)
		if len(h) != 2 {
			continue
		}
		expr := strings.TrimSpace(nftHandlePattern.ReplaceAllString(line, ""))
		updated, ok := replaceNFTQueueExpression(expr, from, to)
		if !ok {
			continue
		}
		fmt.Fprintf(&apply, "replace rule inet %s %s handle %s %s\n", nftTableName, chain, h[1], updated)
		fmt.Fprintf(&rollback, "replace rule inet %s %s handle %s %s\n", nftTableName, chain, h[1], expr)
		matches++
	}
	if matches == 0 {
		return nil, nil, errors.New("no B4 nftables NFQUEUE rules matched the active queue range")
	}
	return []byte(apply.String()), []byte(rollback.String()), nil
}

func replaceNFTQueueExpression(expr string, from, to capture.QueueRange) (string, bool) {
	old := nftQueueText(from)
	if !strings.Contains(expr, old) {
		return expr, false
	}
	return strings.Replace(expr, old, nftQueueText(to), 1), true
}
func nftQueueText(r capture.QueueRange) string {
	if r.Threads > 1 {
		return fmt.Sprintf("queue num %d-%d bypass", r.Start, r.End())
	}
	return fmt.Sprintf("queue num %d bypass", r.Start)
}

func buildIPTablesOwnedChainReplacement(listing []byte, from, to capture.QueueRange) ([]byte, []byte, error) {
	var owned []string
	for _, line := range strings.Split(string(listing), "\n") {
		if strings.HasPrefix(line, "-A B4 ") || strings.HasPrefix(line, "-A B4_PREROUTING ") {
			owned = append(owned, line)
		}
	}
	if len(owned) == 0 {
		return nil, nil, errors.New("B4-owned iptables chains are absent")
	}
	build := func(target capture.QueueRange) ([]byte, int) {
		var out strings.Builder
		out.WriteString("*mangle\n-F B4\n-F B4_PREROUTING\n")
		matches := 0
		for _, line := range owned {
			updated, ok := replaceIPTablesQueueTarget(line, from, target)
			if ok {
				matches++
			}
			out.WriteString(updated)
			out.WriteByte('\n')
		}
		out.WriteString("COMMIT\n")
		return []byte(out.String()), matches
	}
	apply, matches := build(to)
	rollback, _ := build(from)
	if matches == 0 {
		return nil, nil, errors.New("no B4 iptables NFQUEUE rules matched the active queue range")
	}
	return apply, rollback, nil
}

func replaceIPTablesQueueTarget(line string, from, to capture.QueueRange) (string, bool) {
	if !strings.Contains(line, "-j NFQUEUE") {
		return line, false
	}
	old, newValue := iptablesQueueArgs(from), iptablesQueueArgs(to)
	if !strings.Contains(line, old) {
		return line, false
	}
	return strings.Replace(line, old, newValue, 1), true
}
func iptablesQueueArgs(r capture.QueueRange) string {
	if r.Threads > 1 {
		return "--queue-balance " + strconv.Itoa(int(r.Start)) + ":" + strconv.Itoa(int(r.End())) + " --queue-bypass"
	}
	return "--queue-num " + strconv.Itoa(int(r.Start)) + " --queue-bypass"
}
