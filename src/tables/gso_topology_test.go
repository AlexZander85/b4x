package tables

import (
	"context"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/capture"
)

func queueRange(role capture.TopologyQueueRole, start, threads uint16) capture.QueueRange {
	return capture.QueueRange{Role: role, Start: start, Threads: threads, Enabled: true}
}

func TestBuildNFTQueueReplacementUsesAtomicReplaceByHandle(t *testing.T) {
	listing := `table inet b4_mangle {
 chain b4_chain {
  tcp dport 443 counter queue num 537-540 bypass # handle 10
 }
 chain prerouting {
  tcp sport 443 counter queue num 537-540 bypass # handle 11
 }
}`
	apply, rollback, err := buildNFTQueueReplacement([]byte(listing), queueRange(capture.TopologyQueueProduction, 537, 4), queueRange(capture.TopologyQueueProduction, 550, 4))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(apply), "replace rule inet b4_mangle b4_chain handle 10") || !strings.Contains(string(apply), "queue num 550-553 bypass") {
		t.Fatalf("apply=%s", apply)
	}
	if !strings.Contains(string(rollback), "queue num 537-540 bypass") {
		t.Fatalf("rollback=%s", rollback)
	}
	if strings.Contains(string(apply), "flush table") || strings.Contains(string(apply), "delete table") {
		t.Fatalf("global mutation in script: %s", apply)
	}
}

func TestBuildIPTablesReplacementFlushesOnlyOwnedChains(t *testing.T) {
	listing := `*mangle
:PREROUTING ACCEPT [0:0]
:B4 - [0:0]
:B4_PREROUTING - [0:0]
-A B4 -p tcp --dport 443 -j NFQUEUE --queue-balance 537:540 --queue-bypass
-A B4_PREROUTING -p tcp --sport 443 -j NFQUEUE --queue-balance 537:540 --queue-bypass
-A PREROUTING -j B4_PREROUTING
COMMIT`
	apply, rollback, err := buildIPTablesOwnedChainReplacement([]byte(listing), queueRange(capture.TopologyQueueProduction, 537, 4), queueRange(capture.TopologyQueueProduction, 550, 4))
	if err != nil {
		t.Fatal(err)
	}
	text := string(apply)
	if !strings.Contains(text, "-F B4\n-F B4_PREROUTING") || !strings.Contains(text, "--queue-balance 550:553") {
		t.Fatalf("apply=%s", apply)
	}
	if strings.Contains(text, "-F PREROUTING") || strings.Contains(text, ":PREROUTING") {
		t.Fatalf("global chain changed: %s", apply)
	}
	if !strings.Contains(string(rollback), "--queue-balance 537:540") {
		t.Fatalf("rollback=%s", rollback)
	}
}

type memoryTopologyRunner struct {
	calls []string
	fail  int
}

func (r *memoryTopologyRunner) Run(_ context.Context, name string, args []string, input []byte) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " ")+"\n"+string(input))
	return nil, nil
}

func TestQueueTargetReplacementRejectsUnrelatedRanges(t *testing.T) {
	if _, _, err := buildIPTablesOwnedChainReplacement([]byte("*mangle\n:B4 - [0:0]\n:B4_PREROUTING - [0:0]\n-A B4 -j NFQUEUE --queue-num 1 --queue-bypass\nCOMMIT\n"), queueRange(capture.TopologyQueueProduction, 537, 1), queueRange(capture.TopologyQueueProduction, 550, 1)); err == nil {
		t.Fatal("unrelated queue target accepted")
	}
}
