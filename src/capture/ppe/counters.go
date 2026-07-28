package ppe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type RuleCounter struct {
	Family   string `json:"family"`
	Chain    string `json:"chain"`
	Protocol string `json:"protocol"`
	Comment  string `json:"comment"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

type CounterReport struct {
	CapturedAt time.Time     `json:"captured_at"`
	Available  bool          `json:"available"`
	Rules      []RuleCounter `json:"rules,omitempty"`
	Errors     []string      `json:"errors,omitempty"`
}

type RuleCounterCollector struct{ runner Runner }

func NewRuleCounterCollector(runner Runner) *RuleCounterCollector {
	if runner == nil {
		runner = OSRunner{}
	}
	return &RuleCounterCollector{runner: runner}
}

func (c *RuleCounterCollector) Collect(ctx context.Context, desired DesiredState) CounterReport {
	report := CounterReport{CapturedAt: time.Now().UTC()}
	if c == nil || c.runner == nil {
		report.Errors = append(report.Errors, "counter collector unavailable")
		return report
	}
	for _, family := range desired.Families {
		if !family.Enabled {
			continue
		}
		for _, chain := range []string{ChainPre, ChainFwd} {
			args := []string{"-t", "mangle", "-L", chain, "-n", "-v", "-x", "--line-numbers"}
			if family.WaitSupported {
				args = append([]string{"-w"}, args...)
			}
			output, err := c.runner.Run(ctx, family.Binary, args...)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("%s/%s: %v", family.Family, chain, err))
				continue
			}
			report.Available = true
			report.Rules = append(report.Rules, parseRuleCounters(family.Family, chain, output)...)
		}
	}
	return report
}

func parseRuleCounters(family, chain, output string) []RuleCounter {
	var counters []RuleCounter
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		packets, errPackets := strconv.ParseUint(fields[1], 10, 64)
		bytes, errBytes := strconv.ParseUint(fields[2], 10, 64)
		if errPackets != nil || errBytes != nil {
			continue
		}
		comment := ""
		switch {
		case strings.Contains(line, CommentTCP):
			comment = CommentTCP
		case strings.Contains(line, CommentQUIC):
			comment = CommentQUIC
		default:
			continue
		}
		counters = append(counters, RuleCounter{
			Family: family, Chain: chain, Protocol: strings.ToLower(fields[4]), Comment: comment,
			Packets: packets, Bytes: bytes,
		})
	}
	return counters
}
