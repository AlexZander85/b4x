package proton

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestQueuePrefersMeasuredRTTWithinCountry(t *testing.T) {
	nodes := []Node{
		{Name: "slow", Country: "NL", EntryIP: "192.0.2.10", Load: 5, Score: 1, RTT: 220 * time.Millisecond},
		{Name: "unknown", Country: "NL", EntryIP: "192.0.2.11", Load: 1, Score: 0},
		{Name: "fast", Country: "NL", EntryIP: "192.0.2.12", Load: 90, Score: 9, RTT: 25 * time.Millisecond},
	}
	got := NewQueue(nodes, 443).Candidates(Location{Mode: "country", Country: "NL"})
	if len(got) != 3 {
		t.Fatalf("candidates=%d want 3", len(got))
	}
	want := []string{"fast", "slow", "unknown"}
	for i := range want {
		if got[i].Node.Name != want[i] {
			t.Fatalf("candidate[%d]=%s want %s", i, got[i].Node.Name, want[i])
		}
	}
}

func TestQueueWithoutRTTKeepsHistoricalLoadOrdering(t *testing.T) {
	nodes := []Node{
		{Name: "busy", Country: "NL", EntryIP: "192.0.2.20", Load: 80, Score: 1},
		{Name: "idle", Country: "NL", EntryIP: "192.0.2.21", Load: 10, Score: 9},
	}
	got := NewQueue(nodes, 443).Candidates(Location{Mode: "country", Country: "NL"})
	if got[0].Node.Name != "idle" || got[1].Node.Name != "busy" {
		t.Fatalf("unexpected order: %s, %s", got[0].Node.Name, got[1].Node.Name)
	}
}

func TestProbeTCP443RTTProbesEachUniqueEntryIPOnce(t *testing.T) {
	cands := []Candidate{
		{Node: Node{EntryIP: "192.0.2.30"}, Port: 443},
		{Node: Node{EntryIP: "192.0.2.30"}, Port: 51820},
		{Node: Node{EntryIP: "192.0.2.31"}, Port: 88},
		{Node: Node{EntryIP: "192.0.2.32"}, Port: 443},
	}
	var mu sync.Mutex
	calls := map[string]int{}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		calls[address]++
		mu.Unlock()
		if address == "192.0.2.32:443" {
			return nil, errors.New("unreachable")
		}
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	}

	rtts := ProbeTCP443RTT(context.Background(), cands, dial)
	if len(rtts) != 2 {
		t.Fatalf("measured=%d want 2", len(rtts))
	}
	if _, ok := rtts["192.0.2.32"]; ok {
		t.Fatal("failed TCP probe must stay unmeasured")
	}
	for _, addr := range []string{"192.0.2.30:443", "192.0.2.31:443", "192.0.2.32:443"} {
		if calls[addr] != 1 {
			t.Fatalf("calls[%s]=%d want 1", addr, calls[addr])
		}
	}
}
