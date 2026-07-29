package nfq

import (
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

type GSOExecutionScope string

const (
	GSOScopeProduction GSOExecutionScope = "production"
	GSOScopeCandidate  GSOExecutionScope = "candidate"
	GSOScopeDiscovery  GSOExecutionScope = "discovery"
)

type GSOPassToken struct {
	FlowKey        classifier.FlowKey                `json:"flow_key"`
	ClientHelloID  uint64                            `json:"client_hello_id"`
	ConfigGen      uint64                            `json:"config_generation"`
	Decision       classifier.ClassificationDecision `json:"decision"`
	StrategyID     string                            `json:"strategy_id"`
	RequiresAction bool                              `json:"requires_action"`
	ActionToken    action.ActionToken                `json:"action_token"`
	Scope          GSOExecutionScope                 `json:"scope"`
	CreatedAt      time.Time                         `json:"created_at"`
	ExpiresAt      time.Time                         `json:"expires_at"`
}

type GSOPassTokenStoreConfig struct {
	MaxTokens int
	TTL       time.Duration
	Clock     clock.Clock
}

type GSOPassTokenStats struct {
	Created               uint64
	Reused                uint64
	Consumed              uint64
	Misses                uint64
	Stale                 uint64
	Expired               uint64
	Evicted               uint64
	FlowInvalidated       uint64
	GenerationInvalidated uint64
	Cleared               uint64
}

type gsoPassTokenKey struct {
	FlowKey       classifier.FlowKey
	ClientHelloID uint64
	ConfigGen     uint64
	Scope         GSOExecutionScope
}

type gsoPassTokenEntry struct {
	token GSOPassToken
	order uint64
}

type GSOPassTokenStore struct {
	mu      sync.Mutex
	entries map[gsoPassTokenKey]gsoPassTokenEntry
	config  GSOPassTokenStoreConfig
	clock   clock.Clock
	order   uint64
	stats   GSOPassTokenStats
}

func DefaultGSOPassTokenStoreConfig() GSOPassTokenStoreConfig {
	return GSOPassTokenStoreConfig{MaxTokens: 1024, TTL: 5 * time.Second, Clock: clock.RealClock{}}
}

func NewGSOPassTokenStore(cfg GSOPassTokenStoreConfig) *GSOPassTokenStore {
	defaults := DefaultGSOPassTokenStoreConfig()
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = defaults.MaxTokens
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaults.TTL
	}
	if cfg.Clock == nil {
		cfg.Clock = defaults.Clock
	}
	return &GSOPassTokenStore{entries: make(map[gsoPassTokenKey]gsoPassTokenEntry, cfg.MaxTokens), config: cfg, clock: cfg.Clock}
}

func (s *GSOPassTokenStore) Put(token GSOPassToken) (GSOPassToken, bool, error) {
	if s == nil {
		return GSOPassToken{}, false, errors.New("GSO pass token store unavailable")
	}
	token.FlowKey = token.FlowKey.Normalize()
	if token.FlowKey.IsZero() || token.ClientHelloID == 0 || token.ConfigGen == 0 || token.Scope == "" || token.StrategyID == "" {
		return GSOPassToken{}, false, errors.New("invalid GSO pass token identity")
	}
	now := s.clock.Now()
	key := gsoPassTokenKey{FlowKey: token.FlowKey, ClientHelloID: token.ClientHelloID, ConfigGen: token.ConfigGen, Scope: token.Scope}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	if entry, ok := s.entries[key]; ok {
		s.stats.Reused++
		return cloneGSOPassToken(entry.token), true, nil
	}
	for len(s.entries) >= s.config.MaxTokens {
		var oldest gsoPassTokenKey
		var oldestOrder uint64
		first := true
		for candidate, entry := range s.entries {
			if first || entry.order < oldestOrder {
				oldest, oldestOrder, first = candidate, entry.order, false
			}
		}
		if first {
			break
		}
		delete(s.entries, oldest)
		s.stats.Evicted++
	}
	token.CreatedAt = now
	token.ExpiresAt = now.Add(s.config.TTL)
	token.Decision = cloneClassificationDecision(token.Decision)
	s.order++
	s.entries[key] = gsoPassTokenEntry{token: token, order: s.order}
	s.stats.Created++
	return cloneGSOPassToken(token), false, nil
}

func (s *GSOPassTokenStore) Consume(flow classifier.FlowKey, clientHelloID, configGen uint64, scope GSOExecutionScope) (GSOPassToken, bool, string) {
	if s == nil {
		return GSOPassToken{}, false, "store-unavailable"
	}
	key := gsoPassTokenKey{FlowKey: flow.Normalize(), ClientHelloID: clientHelloID, ConfigGen: configGen, Scope: scope}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		s.stats.Misses++
		return GSOPassToken{}, false, "token-miss"
	}
	delete(s.entries, key)
	if !entry.token.ExpiresAt.After(now) {
		s.stats.Stale++
		return GSOPassToken{}, false, "token-stale"
	}
	s.stats.Consumed++
	return cloneGSOPassToken(entry.token), true, "consumed"
}

func (s *GSOPassTokenStore) DeleteFlow(flow classifier.FlowKey) int {
	if s == nil {
		return 0
	}
	flow = flow.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key := range s.entries {
		if key.FlowKey == flow {
			delete(s.entries, key)
			removed++
		}
	}
	s.stats.FlowInvalidated += uint64(removed)
	return removed
}

func (s *GSOPassTokenStore) InvalidateGeneration(generation uint64) int {
	if s == nil || generation == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key := range s.entries {
		if key.ConfigGen == generation {
			delete(s.entries, key)
			removed++
		}
	}
	s.stats.GenerationInvalidated += uint64(removed)
	return removed
}

func (s *GSOPassTokenStore) GC(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneExpiredLocked(now)
}

func (s *GSOPassTokenStore) Clear() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := len(s.entries)
	clear(s.entries)
	s.stats.Cleared += uint64(removed)
	return removed
}

func (s *GSOPassTokenStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *GSOPassTokenStore) Stats() GSOPassTokenStats {
	if s == nil {
		return GSOPassTokenStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *GSOPassTokenStore) pruneExpiredLocked(now time.Time) int {
	removed := 0
	for key, entry := range s.entries {
		if !entry.token.ExpiresAt.After(now) {
			delete(s.entries, key)
			removed++
			s.stats.Expired++
		}
	}
	return removed
}

func cloneGSOPassToken(token GSOPassToken) GSOPassToken {
	token.Decision = cloneClassificationDecision(token.Decision)
	return token
}

func cloneClassificationDecision(decision classifier.ClassificationDecision) classifier.ClassificationDecision {
	decision.Candidates = append([]classifier.Evidence(nil), decision.Candidates...)
	decision.Conflicts = append([]classifier.EvidenceConflict(nil), decision.Conflicts...)
	if decision.Selected != nil {
		selected := *decision.Selected
		decision.Selected = &selected
	}
	return decision
}

func gsoExecutionScope(w *Worker, cfg *config.Config) GSOExecutionScope {
	if w != nil && w.candidate {
		return GSOScopeCandidate
	}
	if cfg != nil && cfg.Queue.IsDiscovery {
		return GSOScopeDiscovery
	}
	return GSOScopeProduction
}

func gsoFlowHash(flow classifier.FlowKey) uint64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%v", flow.Normalize())
	return h.Sum64()
}

func strategyIDForGSO(set *config.SetConfig) string {
	if set == nil {
		return "gso-normalized-action"
	}
	strategy := set.Fragmentation.Strategy
	if strategy == "" || strategy == config.ConfigNone || strategy == config.ConfigOff {
		strategy = "gso-normalized-action"
	}
	return classifierSetID(set) + ":" + strategy
}

func (w *Worker) prepareGSONormalization(vc *verdictCtx, cfg *config.Config, pkt *pktInfo, set *config.SetConfig, flow classifier.FlowKey, clientHelloID, generation uint64, parsedDomain string, tlsVersion uint16, payloadLen int) (int, gsoFastPathResult) {
	if w == nil || vc == nil || w.gsoPassTokens == nil || w.actionTokens == nil || w.normalizerQueue == 0 {
		return vc.accept(), gsoPathActionSuppressed
	}
	scope := nfqDecisionScope{FlowKey: flow, ClientHelloID: clientHelloID, EvidenceConfigGen: generation, CompleteClientHello: true, TLSVersion: tlsVersion}
	decision := w.decideNFQEvidenceScoped(cfg, pkt, flow.DstPort, 6, classifier.TLSMetadata{Version: tlsVersion, ClearSNI: true, HandshakeParsed: true}, scope,
		classifier.Evidence{Source: classifier.EvidencePacketSNI, Domain: parsedDomain, SetID: classifierSetID(set), DomainEvidence: true, CompleteClientHello: true, TLSVersion: tlsVersion, ConfigGen: generation})
	if !decision.CanClassify(classifier.DefaultConfidenceThresholds) || decision.Selected == nil || decision.Selected.SetID != classifierSetID(set) {
		return vc.accept(), gsoPathUnauthorizedFailOpen
	}
	strategyID := strategyIDForGSO(set)
	if existing, ok, _ := w.gsoPassTokens.Peek(flow, clientHelloID, generation, gsoExecutionScope(w, cfg)); ok {
		traceGSOPassToken(existing, "first-pass-retransmission", "requeue-existing")
		return vc.queueTo(w.normalizerQueue), gsoPathNormalizeQueued
	}
	actionResult := w.actionTokens.Claim(action.ActionTokenRequest{
		FlowHash: gsoFlowHash(flow), ClientHelloID: clientHelloID, StrategyID: strategyID, ConfigGen: generation,
		StreamStart: 0, StreamEnd: uint64(payloadLen), InputBytes: payloadLen, Writes: 1, GeneratedBytes: 0,
	})
	if !actionResult.Applied {
		traceGSOFastPath(pkt, requestedGSOMode(cfg), gsoPathActionSuppressed, actionResult.Reason, clientHelloID)
		return vc.accept(), gsoPathActionSuppressed
	}
	token, _, err := w.gsoPassTokens.Put(GSOPassToken{
		FlowKey: flow, ClientHelloID: clientHelloID, ConfigGen: generation, Decision: decision,
		StrategyID: strategyID, RequiresAction: true, ActionToken: actionResult.Token, Scope: gsoExecutionScope(w, cfg),
	})
	if err != nil {
		return vc.accept(), gsoPathActionSuppressed
	}
	traceGSOPassToken(token, "first-pass", "queued")
	return vc.queueTo(w.normalizerQueue), gsoPathNormalizeQueued
}

func (s *GSOPassTokenStore) Peek(flow classifier.FlowKey, clientHelloID, configGen uint64, scope GSOExecutionScope) (GSOPassToken, bool, string) {
	if s == nil {
		return GSOPassToken{}, false, "store-unavailable"
	}
	key := gsoPassTokenKey{FlowKey: flow.Normalize(), ClientHelloID: clientHelloID, ConfigGen: configGen, Scope: scope}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return GSOPassToken{}, false, "token-miss"
	}
	if !entry.token.ExpiresAt.After(now) {
		delete(s.entries, key)
		s.stats.Stale++
		return GSOPassToken{}, false, "token-stale"
	}
	return cloneGSOPassToken(entry.token), true, "found"
}

func traceGSOPassToken(token GSOPassToken, pass, result string) {
	observability.Default().Trace.Record(observability.TraceEvent{Timestamp: time.Now(), FlowID: fmt.Sprintf("%v", token.FlowKey), Kind: "gso_pass_token", Fields: map[string]string{
		"pass": pass, "result": result, "client_hello_id": fmt.Sprintf("%d", token.ClientHelloID), "config_generation": fmt.Sprintf("%d", token.ConfigGen),
		"strategy_id": token.StrategyID, "scope": string(token.Scope), "requires_action": fmt.Sprintf("%t", token.RequiresAction),
	}})
}
