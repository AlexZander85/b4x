package ppe

import (
	"context"
	"strings"
	"testing"
)

func TestIPTablesBackendCleansDuplicatesAndVerifiesCanonicalState(t *testing.T) {
	runner := newMemoryIPTablesRunner()
	runner.chains[ChainPre] = [][]string{{"-A", ChainPre, "-p", "tcp", "--dport", "80", "-j", "PPE"}, {"-A", ChainPre, "-p", "tcp", "--dport", "80", "-j", "PPE"}}
	runner.chains[ChainFwd] = [][]string{{"-A", ChainFwd, "-p", "tcp", "--dport", "80", "-j", "PPE"}}
	preJump := []string{"-A", "PREROUTING", "-m", "comment", "--comment", CommentJumpPre, "-j", ChainPre}
	fwdJump := []string{"-A", "FORWARD", "-m", "comment", "--comment", CommentJumpFwd, "-j", ChainFwd}
	runner.hooks["PREROUTING"] = [][]string{cloneArgs(preJump), cloneArgs(preJump)}
	runner.hooks["FORWARD"] = [][]string{cloneArgs(fwdJump), cloneArgs(fwdJump)}

	plan := FamilyPlan{
		Family: "ipv4", Binary: "iptables", WaitSupported: true, Enabled: true,
		Rules: []string{
			"-A B4_PPE_PRE -p tcp --dport 443 -m comment --comment b4:ppe:v1:tcp -j PPE",
			"-A B4_PPE_FWD -p tcp --dport 443 -m comment --comment b4:ppe:v1:tcp -j PPE",
		},
	}
	backend := NewIPTablesBackend(runner)
	if err := backend.Install(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := backend.Verify(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	snapshot, err := backend.Snapshot(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.PreJumps) != 1 || len(snapshot.FwdJumps) != 1 || len(snapshot.PreRules) != 1 || len(snapshot.FwdRules) != 1 {
		t.Fatalf("duplicates remain: %+v", snapshot)
	}
}

func TestIPTablesBackendRejectsForeignReferenceBeforeMutation(t *testing.T) {
	runner := newMemoryIPTablesRunner()
	runner.chains[ChainPre] = [][]string{{"-A", ChainPre, "-p", "tcp", "-j", "PPE"}}
	runner.chains[ChainFwd] = nil
	runner.hooks["FORWARD"] = [][]string{{"-A", "FORWARD", "-m", "comment", "--comment", "other:owner", "-j", ChainPre}}
	backend := NewIPTablesBackend(runner)
	plan := FamilyPlan{Family: "ipv4", Binary: "iptables", WaitSupported: true, Enabled: true}
	if err := backend.Install(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "foreign rule") {
		t.Fatalf("foreign reference accepted: %v", err)
	}
	if _, ok := runner.chains[ChainPre]; !ok || len(runner.hooks["FORWARD"]) != 1 {
		t.Fatal("backend mutated state before conflict validation")
	}
}

func TestIPTablesBackendRestorePreservesPreviousJumpPositions(t *testing.T) {
	runner := newMemoryIPTablesRunner()
	runner.hooks["PREROUTING"] = [][]string{{"-A", "PREROUTING", "-p", "icmp", "-j", "ACCEPT"}}
	runner.hooks["FORWARD"] = [][]string{{"-A", "FORWARD", "-p", "icmp", "-j", "ACCEPT"}, {"-A", "FORWARD", "-p", "udp", "-j", "ACCEPT"}}
	backend := NewIPTablesBackend(runner)
	snapshot := oldSnapshot("ipv4", "iptables", "old")
	if err := backend.Restore(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	got, err := backend.Snapshot(context.Background(), FamilyPlan{Family: "ipv4", Binary: "iptables", WaitSupported: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.PreJumps[0].Position != 2 || got.FwdJumps[0].Position != 3 {
		t.Fatalf("jump positions not restored: pre=%v fwd=%v", got.PreJumps, got.FwdJumps)
	}
}
