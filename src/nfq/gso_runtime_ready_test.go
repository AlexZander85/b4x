package nfq

import (
	"testing"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/fixtures"
)

// TestGSONormalizerMutationRequiresFullActionCapability asserts the
// GSO_RUNTIME_READY first-pass gate: a set that needs normal-packet mutation
// is never queued for normalization while the runtime only holds
// classify-ready capability — the packet is accepted unchanged.
func TestGSONormalizerMutationRequiresFullActionCapability(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeFull, true, false)
	cfg.System.Classifier.Runtime.Execution.GSOPolicy = config.GSOPolicyNormalizeForAction
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 56000)
	first := NewWorkerWithQueue(cfg, 0)
	first.setGSOCapabilityStatus(GSOCapabilityClassifyReady, "unit target capability")
	first.SetGSOReadinessEvidence(fullGSOReadinessEvidence(dnsHintConfigGeneration(cfg)))
	first.configureGSONormalizer(650, false)
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result := first.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 56000, 443, 12345, true)
	if !handled || result != gsoPathActionSuppressed || vc.verdict != engine.VerdictAccept {
		t.Fatalf("handled=%t result=%s verdict=%v want action-suppressed", handled, result, vc.verdict)
	}
	if first.gsoPassTokens.Len() != 0 {
		t.Fatalf("token created without full-action runtime: %d", first.gsoPassTokens.Len())
	}
}

// TestGSONormalizerSecondaryRequiresRuntimeReady asserts the GSO_RUNTIME_READY
// secondary-pass gate: a valid token is never executed while the normalizer
// worker does not hold full-action capability.
func TestGSONormalizerSecondaryRequiresRuntimeReady(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeFull, true, false)
	cfg.System.Classifier.Runtime.Execution.GSOPolicy = config.GSOPolicyNormalizeForAction
	cfg.System.Classifier.Runtime.Execution.GSOFullConfirmation = config.GSOFullConfirmation
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 56000)
	first := NewWorkerWithQueue(cfg, 0)
	first.setGSOCapabilityStatus(GSOCapabilityFullActionReady, "unit target capability")
	first.SetGSOReadinessEvidence(fullGSOReadinessEvidence(dnsHintConfigGeneration(cfg)))
	first.configureGSONormalizer(650, false)
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result := first.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 56000, 443, 12345, true)
	if !handled || result != gsoPathNormalizeQueued || first.gsoPassTokens.Len() != 1 {
		t.Fatalf("first pass handled=%t result=%s tokens=%d", handled, result, first.gsoPassTokens.Len())
	}

	secondary := NewWorkerWithQueue(cfg, 650)
	secondary.gsoPassTokens = first.gsoPassTokens
	secondary.configureGSONormalizer(650, true)
	if _, _, ok, reason := secondary.consumeGSOPassForPacket(cfg, pkt, 56000, 443, 12345, true); ok || reason != "runtime-not-ready" {
		t.Fatalf("ok=%t reason=%q want runtime-not-ready without full-action capability", ok, reason)
	}
}

func normalizerWorkerWithStoredToken(t *testing.T, mutateToken func(*GSOPassToken)) (*Worker, *config.Config) {
	t.Helper()
	cfg, _ := testGSOFastPathConfig(config.GSOModeFull, true, false)
	cfg.System.Classifier.Runtime.Execution.GSOPolicy = config.GSOPolicyNormalizeForAction
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 56000)
	generation := dnsHintConfigGeneration(cfg)
	flow, ok := tcpFlowKeyForPacket(pkt, 56000, 443)
	if !ok {
		t.Fatal("flow key unavailable")
	}
	helloID := classifier.LogicalClientHelloID(flow, 12345, generation)
	store := NewGSOPassTokenStore(DefaultGSOPassTokenStoreConfig())
	token := testGSOToken(flow, helloID, generation, GSOScopeProduction)
	// testGSOToken carries the scoped-hints policy digest; the fixture config
	// resolves strict, so align the compact references with the active set.
	token.EffectivePolicyID = effectivePolicyDigestForGSO("youtube", cfg.EffectiveDomainPolicy(cfg.Sets[0]))
	token.AuthorizationID = authorizationDigestForGSO(flow, "youtube", generation)
	mutateToken(&token)
	if _, _, err := store.Put(token); err != nil {
		t.Fatalf("put token: %v", err)
	}
	secondary := NewWorkerWithQueue(cfg, 650)
	secondary.gsoPassTokens = store
	secondary.setGSOCapabilityStatus(GSOCapabilityFullActionReady, "unit target capability")
	secondary.SetGSOReadinessEvidence(fullGSOReadinessEvidence(generation))
	secondary.configureGSONormalizer(650, true)
	return secondary, cfg
}

// TestGSONormalizerSecondaryRejectsRevokedAuthorization asserts that a token
// whose authorization digest no longer matches the active generation fails
// open on the secondary pass.
func TestGSONormalizerSecondaryRejectsRevokedAuthorization(t *testing.T) {
	secondary, cfg := normalizerWorkerWithStoredToken(t, func(token *GSOPassToken) {
		token.AuthorizationID = "auth-0000000000000000"
	})
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 56000)
	_, _, ok, reason := secondary.consumeGSOPassForPacket(cfg, pkt, 56000, 443, 12345, true)
	if ok || reason != "authorization-revoked" {
		t.Fatalf("ok=%t reason=%q want authorization-revoked", ok, reason)
	}
}

// TestGSONormalizerSecondaryRejectsRevokedPolicy asserts that a token whose
// effective-policy digest no longer matches the active generation fails open
// on the secondary pass.
func TestGSONormalizerSecondaryRejectsRevokedPolicy(t *testing.T) {
	secondary, cfg := normalizerWorkerWithStoredToken(t, func(token *GSOPassToken) {
		token.EffectivePolicyID = "policy-0000000000000000"
	})
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 56000)
	_, _, ok, reason := secondary.consumeGSOPassForPacket(cfg, pkt, 56000, 443, 12345, true)
	if ok || reason != "policy-revoked" {
		t.Fatalf("ok=%t reason=%q want policy-revoked", ok, reason)
	}
}

// TestGSONormalizerSecondaryConsumesValidToken asserts the happy path still
// executes a token that matches the active generation.
func TestGSONormalizerSecondaryConsumesValidToken(t *testing.T) {
	secondary, cfg := normalizerWorkerWithStoredToken(t, func(token *GSOPassToken) {})
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 56000)
	token, set, ok, reason := secondary.consumeGSOPassForPacket(cfg, pkt, 56000, 443, 12345, true)
	if !ok || reason != "consumed" || set == nil || set.Id != "youtube" || token.ClientHelloID == 0 {
		t.Fatalf("ok=%t reason=%q set=%v", ok, reason, set)
	}
}
