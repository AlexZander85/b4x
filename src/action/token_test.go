package action

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func tokenRequest(flow uint64, generation uint64) ActionTokenRequest {
	return ActionTokenRequest{FlowHash: flow, StrategyID: "split", ConfigGen: generation, StreamStart: 0, StreamEnd: 10, InputBytes: 100, Writes: 2, GeneratedBytes: 20}
}

func TestActionTokenStoreSuppressesRetransmissionAndOverlap(t *testing.T) {
	store := NewActionTokenStore(ActionTokenStoreConfig{MaxFlows: 8, Timeout: time.Minute, Clock: clock.NewFixed(time.Unix(3000, 0)), Budgets: DefaultActionBudgets()})
	first := store.Claim(tokenRequest(1, 7))
	if !first.Applied || first.Token.ClientHelloID == 0 {
		t.Fatalf("first token = %+v", first)
	}
	for _, request := range []ActionTokenRequest{tokenRequest(1, 7), func() ActionTokenRequest { r := tokenRequest(1, 7); r.StreamStart, r.StreamEnd = 5, 15; return r }(), func() ActionTokenRequest { r := tokenRequest(1, 7); r.StreamStart, r.StreamEnd = 20, 30; return r }()} {
		result := store.Claim(request)
		if !result.Suppressed || result.Token != first.Token {
			t.Fatalf("retransmission result = %+v", result)
		}
	}
	second := store.Claim(tokenRequest(2, 7))
	if !second.Applied || second.Token.FlowHash != 2 {
		t.Fatalf("new flow token = %+v", second)
	}
	if store.Stats().Reused == 0 || store.Stats().Suppressed < 3 {
		t.Fatalf("idempotency stats = %+v", store.Stats())
	}
}

func TestActionTokenStoreLifecycleGenerationAndRetry(t *testing.T) {
	clk := clock.NewFixed(time.Unix(3100, 0))
	store := NewActionTokenStore(ActionTokenStoreConfig{MaxFlows: 4, Timeout: time.Second, Clock: clk, Budgets: DefaultActionBudgets()})
	if !store.Claim(tokenRequest(3, 8)).Applied {
		t.Fatal("initial claim failed")
	}
	if !store.CloseServerProgress(3) {
		t.Fatal("server progress did not close token")
	}
	closed := store.Claim(tokenRequest(3, 8))
	if !closed.Suppressed || closed.Reason != "server progress closed first-flight window" {
		t.Fatalf("closed token = %+v", closed)
	}
	clk.Advance(2 * time.Second)
	if store.GC(clk.Now()) != 1 || !store.Claim(tokenRequest(3, 8)).Applied {
		t.Fatalf("timeout/retry lifecycle failed stats=%+v", store.Stats())
	}
	if removed := store.InvalidateGeneration(8); removed != 1 {
		t.Fatalf("generation invalidation removed=%d", removed)
	}
	if result := store.Claim(tokenRequest(3, 8)); !result.Suppressed || result.Reason != "config generation invalidated" {
		t.Fatalf("invalidated generation result=%+v", result)
	}
	if result := store.Claim(tokenRequest(3, 9)); !result.Applied {
		t.Fatalf("new generation claim=%+v", result)
	}
}

func TestActionTokenStoreBudgetsAndProcessedMark(t *testing.T) {
	budgets := ActionBudgets{MaxWritesPerHello: 2, MaxFakeBytes: 10, MaxAmplification: 2}
	store := NewActionTokenStore(ActionTokenStoreConfig{MaxFlows: 4, Timeout: time.Minute, Clock: clock.NewFixed(time.Unix(3200, 0)), Budgets: budgets})
	tooManyWrites := tokenRequest(4, 1)
	tooManyWrites.Writes = 3
	if result := store.Claim(tooManyWrites); !result.Suppressed || result.Reason == "" {
		t.Fatalf("write budget result=%+v", result)
	}
	tooMuchAmplification := tokenRequest(5, 1)
	tooMuchAmplification.GeneratedBytes = 150
	if result := store.Claim(tooMuchAmplification); !result.Suppressed {
		t.Fatalf("amplification budget result=%+v", result)
	}
	marked := tokenRequest(6, 1)
	marked.PacketMark = 0x4001
	marked.ProcessedMark = 0x4000
	if result := store.Claim(marked); !result.Suppressed || result.Reason != "processed provenance mark" {
		t.Fatalf("processed mark result=%+v", result)
	}
}

func FuzzActionTokenStoreNeverPanics(f *testing.F) {
	f.Add(uint64(1), uint64(7), uint64(10), uint64(20))
	f.Fuzz(func(t *testing.T, flow, generation, start, length uint64) {
		if flow == 0 {
			flow = 1
		}
		if length == 0 {
			length = 1
		}
		store := NewActionTokenStore(ActionTokenStoreConfig{MaxFlows: 4, Timeout: time.Second, Clock: clock.NewFixed(time.Unix(3300, 0)), Budgets: DefaultActionBudgets()})
		store.Claim(ActionTokenRequest{FlowHash: flow, ClientHelloID: generation, ConfigGen: generation, StreamStart: start, StreamEnd: start + length, InputBytes: 100, Writes: 1, GeneratedBytes: 1})
		store.CloseServerProgress(flow)
		store.GC(time.Unix(3302, 0))
	})
}

func BenchmarkActionTokenClaimSuppress(b *testing.B) {
	store := NewActionTokenStore(ActionTokenStoreConfig{MaxFlows: 4, Timeout: time.Minute, Clock: clock.NewFixed(time.Unix(3400, 0)), Budgets: DefaultActionBudgets()})
	request := tokenRequest(10, 1)
	if !store.Claim(request).Applied {
		b.Fatal("initial claim failed")
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.Claim(request)
	}
}
