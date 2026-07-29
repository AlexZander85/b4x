package action

import (
	"strconv"

	"github.com/daniellavrushin/b4/observability"
)

func (s *ActionTokenStore) Claim(request ActionTokenRequest) ActionTokenResult {
	if s == nil || request.FlowHash == 0 || request.StreamEnd <= request.StreamStart {
		observability.Default().Metrics.Inc(observability.MetricTCPActionSuppressed, map[string]string{"reason": "invalid-request"}, 1)
		return ActionTokenResult{Suppressed: true, Reason: "invalid action token request"}
	}
	if request.PacketMark != 0 && IsProcessedMark(request.PacketMark, request.ProcessedMark) {
		observability.Default().Metrics.Inc(observability.MetricTCPActionSuppressed, map[string]string{"reason": "processed-mark"}, 1)
		return ActionTokenResult{Suppressed: true, Reason: "processed provenance mark"}
	}
	if err := s.config.Budgets.Check(request.InputBytes, request.Writes, request.GeneratedBytes); err != nil {
		s.mu.Lock()
		s.stats.BudgetRejected++
		s.mu.Unlock()
		observability.Default().Metrics.Inc(observability.MetricTCPActionSuppressed, map[string]string{"reason": "budget"}, 1)
		return ActionTokenResult{Suppressed: true, Reason: err.Error()}
	}
	if request.InputBytes > 0 {
		amplification := float64(request.InputBytes+request.GeneratedBytes) / float64(request.InputBytes)
		observability.Default().Metrics.Observe(observability.MetricTCPPacketAmplification, map[string]string{"result": "claim"}, amplification)
	}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Claims++
	s.pruneExpiredLocked(now)
	if _, invalid := s.invalidated[request.ConfigGen]; invalid && request.ConfigGen != 0 {
		s.stats.GenerationInvalidated++
		observability.Default().Metrics.Inc(observability.MetricTCPActionSuppressed, map[string]string{"reason": "generation-invalidated"}, 1)
		return ActionTokenResult{Suppressed: true, Reason: "config generation invalidated"}
	}
	if entry := s.entries[request.FlowHash]; entry != nil {
		if entry.token.ConfigGen != request.ConfigGen {
			delete(s.entries, request.FlowHash)
		} else {
			entry.lastSeen = now
			s.order++
			entry.order = s.order
			s.stats.Suppressed++
			if entry.closed {
				observability.Default().Metrics.Inc(observability.MetricTCPActionSuppressed, map[string]string{"reason": "server-progress"}, 1)
				return ActionTokenResult{Suppressed: true, Reason: "server progress closed first-flight window", Token: entry.token}
			}
			s.stats.Reused++
			observability.Default().Metrics.Inc(observability.MetricTCPActionTokenReuse, map[string]string{"config_generation": strconv.FormatUint(request.ConfigGen, 10)}, 1)
			observability.Default().Metrics.Inc(observability.MetricTCPActionSuppressed, map[string]string{"reason": "retransmission"}, 1)
			return ActionTokenResult{Reused: true, Suppressed: true, Reason: "logical ClientHello already claimed", Token: entry.token}
		}
	}
	for len(s.entries) >= s.config.MaxFlows {
		oldest := s.oldestFlowLocked()
		if oldest == 0 {
			break
		}
		delete(s.entries, oldest)
		s.stats.Evicted++
	}
	s.nextHelloID++
	helloID := request.ClientHelloID
	if helloID == 0 {
		helloID = s.nextHelloID
	}
	token := ActionToken{FlowHash: request.FlowHash, ClientHelloID: helloID, StrategyID: request.StrategyID, ConfigGen: request.ConfigGen}
	s.order++
	s.entries[request.FlowHash] = &actionTokenEntry{token: token, streamStart: request.StreamStart, streamEnd: request.StreamEnd, lastSeen: now, order: s.order}
	s.stats.Applied++
	observability.Default().Metrics.Inc(observability.MetricTCPActionTokenReuse, map[string]string{"config_generation": strconv.FormatUint(request.ConfigGen, 10), "result": "claimed"}, 1)
	return ActionTokenResult{Applied: true, Reason: "first logical ClientHello action claimed", Token: token}
}
