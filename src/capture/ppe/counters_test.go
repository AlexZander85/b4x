package ppe

import (
	"context"
	"os"
	"strings"
	"testing"
)

type counterRunner struct{ output string }

func (c counterRunner) ReadFile(string) ([]byte, error)                        { return nil, os.ErrNotExist }
func (c counterRunner) Stat(string) (os.FileInfo, error)                       { return nil, os.ErrNotExist }
func (c counterRunner) LookPath(file string) (string, error)                   { return file, nil }
func (c counterRunner) Run(context.Context, string, ...string) (string, error) { return c.output, nil }

func TestParseRuleCountersOnlyOwnedRules(t *testing.T) {
	output := `Chain B4_PPE_PRE (1 references)
num      pkts      bytes target prot opt in out source destination
1 12 1200 PPE tcp -- * * 0.0.0.0/0 0.0.0.0/0 /* b4:ppe:v1:tcp */
2 3 333 PPE udp -- * * 0.0.0.0/0 0.0.0.0/0 /* b4:ppe:v1:quic */
3 99 9999 ACCEPT all -- * * 0.0.0.0/0 0.0.0.0/0`
	got := parseRuleCounters("ipv4", ChainPre, output)
	if len(got) != 2 || got[0].Packets != 12 || got[0].Bytes != 1200 || got[1].Comment != CommentQUIC {
		t.Fatalf("counters=%+v", got)
	}
}

func TestCounterCollectorUsesWaitAndDoesNotInventCounters(t *testing.T) {
	runner := &recordingCounterRunner{}
	collector := NewRuleCounterCollector(runner)
	desired := DesiredState{Families: []FamilyPlan{{Family: "ipv4", Binary: "iptables", WaitSupported: true, Enabled: true}}}
	report := collector.Collect(context.Background(), desired)
	if !report.Available || len(report.Rules) != 0 || len(runner.calls) != 2 {
		t.Fatalf("report=%+v calls=%v", report, runner.calls)
	}
	for _, call := range runner.calls {
		if !strings.Contains(call, "iptables -w -t mangle -L B4_PPE_") {
			t.Fatalf("missing wait/owned chain: %s", call)
		}
	}
}

type recordingCounterRunner struct{ calls []string }

func (r *recordingCounterRunner) ReadFile(string) ([]byte, error)      { return nil, os.ErrNotExist }
func (r *recordingCounterRunner) Stat(string) (os.FileInfo, error)     { return nil, os.ErrNotExist }
func (r *recordingCounterRunner) LookPath(file string) (string, error) { return file, nil }
func (r *recordingCounterRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return "Chain B4_PPE (0 references)\nnum pkts bytes target prot opt in out source destination", nil
}
