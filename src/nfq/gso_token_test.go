package nfq

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/fixtures"
)

func testGSOToken(flow classifier.FlowKey, helloID, generation uint64, scope GSOExecutionScope) GSOPassToken {
	selected := classifier.Evidence{Source: classifier.EvidencePacketSNI, FlowKey: flow, ClientHelloID: helloID, ConfigGen: generation, Domain: "api.youtube.com", SetID: "youtube", DomainEvidence: true, CompleteClientHello: true, Confidence: 100}
	return GSOPassToken{
		FlowKey: flow, ClientHelloID: helloID, ConfigGen: generation, StrategyID: "youtube:split", RequiresAction: true, Scope: scope,
		Decision:    classifier.ClassificationDecision{FlowKey: flow, ClientHelloID: helloID, ConfigGen: generation, Selected: &selected, Candidates: []classifier.Evidence{selected}, Final: true, Confidence: 100},
		ActionToken: action.ActionToken{FlowHash: gsoFlowHash(flow), ClientHelloID: helloID, ConfigGen: generation, StrategyID: "youtube:split"},
	}
}

func gsoTokenTestFlowKey() classifier.FlowKey {
	client := classifier.ClientKey{
		L3Family: 4,
		SourceIP: netip.MustParseAddr("192.0.2.44"),
		IfIndex:  4,
		VLAN:     44,
	}
	return classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.44"), 51444, 443, 6)
}

func TestGSOPassTokenStoreDeterministicRetransmissionAndConsumeOnce(t *testing.T) {
	clk := clock.NewFixed(time.Unix(2000, 0))
	store := NewGSOPassTokenStore(GSOPassTokenStoreConfig{MaxTokens: 4, TTL: time.Second, Clock: clk})
	flow := gsoTokenTestFlowKey()
	first, reused, err := store.Put(testGSOToken(flow, 9, 7, GSOScopeProduction))
	if err != nil || reused {
		t.Fatalf("first put = %+v reused=%t err=%v", first, reused, err)
	}
	second, reused, err := store.Put(testGSOToken(flow, 9, 7, GSOScopeProduction))
	if err != nil || !reused || second.CreatedAt != first.CreatedAt || second.ExpiresAt != first.ExpiresAt || store.Len() != 1 {
		t.Fatalf("retransmission changed token: first=%+v second=%+v reused=%t err=%v", first, second, reused, err)
	}
	consumed, ok, reason := store.Consume(flow, 9, 7, GSOScopeProduction)
	if !ok || reason != "consumed" || consumed.ActionToken != first.ActionToken || store.Len() != 0 {
		t.Fatalf("consume = %+v ok=%t reason=%s", consumed, ok, reason)
	}
	if _, ok, reason = store.Consume(flow, 9, 7, GSOScopeProduction); ok || reason != "token-miss" {
		t.Fatalf("second consume must fail: ok=%t reason=%s", ok, reason)
	}
}

func TestGSOPassTokenStoreIsolatesScopeGenerationAndDoesNotSlideTTL(t *testing.T) {
	clk := clock.NewFixed(time.Unix(2100, 0))
	store := NewGSOPassTokenStore(GSOPassTokenStoreConfig{MaxTokens: 4, TTL: time.Second, Clock: clk})
	flow := gsoTokenTestFlowKey()
	original, _, _ := store.Put(testGSOToken(flow, 11, 17, GSOScopeProduction))
	clk.Advance(750 * time.Millisecond)
	reused, wasReused, _ := store.Put(testGSOToken(flow, 11, 17, GSOScopeProduction))
	if !wasReused || reused.ExpiresAt != original.ExpiresAt {
		t.Fatalf("retransmission slid TTL: original=%v reused=%v", original.ExpiresAt, reused.ExpiresAt)
	}
	if _, ok, reason := store.Consume(flow, 11, 17, GSOScopeCandidate); ok || reason != "token-miss" {
		t.Fatalf("candidate consumed production token: ok=%t reason=%s", ok, reason)
	}
	if _, ok, reason := store.Consume(flow, 11, 18, GSOScopeProduction); ok || reason != "token-miss" {
		t.Fatalf("new generation consumed old token: ok=%t reason=%s", ok, reason)
	}
	clk.Advance(251 * time.Millisecond)
	if _, ok, reason := store.Consume(flow, 11, 17, GSOScopeProduction); ok || reason != "token-stale" {
		t.Fatalf("expired token accepted: ok=%t reason=%s", ok, reason)
	}
}

func TestGSOPassTokenStoreBoundedAndLifecycleCleanup(t *testing.T) {
	store := NewGSOPassTokenStore(GSOPassTokenStoreConfig{MaxTokens: 2, TTL: time.Minute, Clock: clock.NewFixed(time.Unix(2200, 0))})
	flow := gsoTokenTestFlowKey()
	for i := uint64(1); i <= 3; i++ {
		if _, _, err := store.Put(testGSOToken(flow, i, i, GSOScopeProduction)); err != nil {
			t.Fatal(err)
		}
	}
	if store.Len() != 2 || store.Stats().Evicted != 1 {
		t.Fatalf("bounded store mismatch len=%d stats=%+v", store.Len(), store.Stats())
	}
	if removed := store.InvalidateGeneration(2); removed != 1 {
		t.Fatalf("generation cleanup removed=%d", removed)
	}
	if removed := store.DeleteFlow(flow); removed != 1 || store.Len() != 0 {
		t.Fatalf("flow cleanup removed=%d len=%d", removed, store.Len())
	}
}

func TestGSONormalizerFirstPassQueuesAndSecondaryConsumesSameIdentityOnce(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeClassify, true, false)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 56000)
	first := NewWorkerWithQueue(cfg, 0)
	first.setGSOCapabilityStatus(GSOCapabilityClassifyReady, "unit target capability")
	first.configureGSONormalizer(650, false)
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result := first.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 56000, 443, 12345, true)
	if !handled || result != gsoPathNormalizeQueued || vc.queuedTo != 650 || first.gsoPassTokens.Len() != 1 {
		t.Fatalf("first pass handled=%t result=%s queued=%d tokens=%d", handled, result, vc.queuedTo, first.gsoPassTokens.Len())
	}

	secondary := NewWorkerWithQueue(cfg, 650)
	secondary.gsoPassTokens = first.gsoPassTokens
	secondary.actionTokens = first.actionTokens
	secondary.configureGSONormalizer(650, true)
	token, set, ok, reason := secondary.consumeGSOPassForPacket(cfg, pkt, 56000, 443, 12345, true)
	if !ok || reason != "consumed" || set == nil || token.ClientHelloID == 0 || token.ActionToken.ClientHelloID != token.ClientHelloID {
		t.Fatalf("secondary token=%+v set=%+v ok=%t reason=%s", token, set, ok, reason)
	}
	if _, _, ok, reason = secondary.consumeGSOPassForPacket(cfg, pkt, 56000, 443, 12345, true); ok || reason != "token-miss" {
		t.Fatalf("secondary replay was not suppressed: ok=%t reason=%s", ok, reason)
	}
}

func TestNFQueueNumberVerdictEncoding(t *testing.T) {
	const queue = uint16(650)
	want := int((uint32(queue) << 16) | 3)
	if got := nfQueueVerdictFor(queue); got != want {
		t.Fatalf("verdict=%#x want=%#x", got, want)
	}
}
