package nfq

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
)

func activePassiveRSTConfig(mode string) config.PassiveRSTRuntimeConfig {
	cfg := passiveRSTTestConfig()
	cfg.Mode = mode
	cfg.SetScopes = []string{"youtube"}
	cfg.DeviceScopes = []string{"aa:bb:cc:dd:ee:01"}
	cfg.SuppressionWindowSeconds = 5
	cfg.GlobalSuppressionsPerMinute = 8
	return cfg
}

func forgedPassiveRSTEvidence(t *testing.T, store *PassiveRSTStore, flow classifier.FlowKey, generation uint64, now time.Time) PassiveRSTEvidence {
	t.Helper()
	rst := serverObservation(classifier.TCPFlagRST, 9000, 0, 0, 30, 0, now)
	rst.OptionsFingerprint = 0
	rst.IPID = 10000
	evidence, tracked := store.ObserveIncoming(flow.Client.SourceIP.String(), "203.0.113.10", flowClientPort(flow), 443, generation, rst)
	if !tracked {
		t.Fatal("forged RST was not tracked")
	}
	return evidence
}

func TestPassiveRSTConservativeSuppressesImpossibleWindowWithExactSafetyGates(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	clk := clock.NewFixed(now)
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clk)
	flow := passiveRSTTestFlow(1, 52000)
	establishPassiveRSTFlow(t, store, flow, 21, now, false)
	evidence := forgedPassiveRSTEvidence(t, store, flow, 21, now.Add(50*time.Millisecond))
	result := store.Enforce(activePassiveRSTConfig(config.PassiveRSTConservative), evidence)
	if !result.Suppress() || result.EffectiveMode != config.PassiveRSTConservative || result.BudgetRemaining != 1 {
		t.Fatalf("result=%+v evidence=%+v", result, evidence)
	}
	if stats := store.Stats(); stats.Suppressed != 1 || stats.FailOpen != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPassiveRSTConservativeRequiresStrongPlusIndependentCorroboration(t *testing.T) {
	now := time.Unix(2100, 0).UTC()
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))
	flow := passiveRSTTestFlow(2, 52001)
	store.ObserveOutgoing(flow, 22, clientObservation(classifier.TCPFlagSYN, 100, 0, 4096, now))
	_, _ = store.ObserveIncoming("192.0.2.2", "203.0.113.10", 52001, 443, 22,
		serverObservation(classifier.TCPFlagSYN|classifier.TCPFlagACK, 1000, 101, 4096, 52, 0, now.Add(time.Millisecond)))
	// A reliable in-window RST with no independent corroborating signal has only
	// the pre-payload strong signal and must remain observe-only.
	rst := serverObservation(classifier.TCPFlagRST|classifier.TCPFlagACK, 1000, 101, 4096, 52, 0, now.Add(2*time.Millisecond))
	evidence, _ := store.ObserveIncoming("192.0.2.2", "203.0.113.10", 52001, 443, 22, rst)
	result := store.Enforce(activePassiveRSTConfig(config.PassiveRSTConservative), evidence)
	if result.Decision != PassiveRSTDecisionObserve || result.StrongSignals == 0 || result.CorroboratingSignals != 0 {
		t.Fatalf("result=%+v evidence=%+v", result, evidence)
	}
}

func TestPassiveRSTLegitimateAndIncompleteVisibilityFlowsFailOpen(t *testing.T) {
	now := time.Unix(2200, 0).UTC()
	cfg := activePassiveRSTConfig(config.PassiveRSTConservative)
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))

	closed := passiveRSTTestFlow(3, 52002)
	store.ObserveOutgoing(closed, 23, clientObservation(classifier.TCPFlagSYN, 1, 0, 1000, now))
	rst := serverObservation(classifier.TCPFlagRST|classifier.TCPFlagACK, 1, 2, 1000, 52, 0, now.Add(time.Millisecond))
	evidence, _ := store.ObserveIncoming("192.0.2.3", "203.0.113.10", 52002, 443, 23, rst)
	if result := store.Enforce(cfg, evidence); result.Decision != PassiveRSTDecisionPass {
		t.Fatalf("closed-port result=%+v", result)
	}

	progress := passiveRSTTestFlow(4, 52003)
	establishPassiveRSTFlow(t, store, progress, 24, now, true)
	evidence = forgedPassiveRSTEvidence(t, store, progress, 24, now.Add(50*time.Millisecond))
	if result := store.Enforce(cfg, evidence); result.Decision != PassiveRSTDecisionPass {
		t.Fatalf("server-progress result=%+v", result)
	}

	incomplete := passiveRSTTestFlow(5, 52004)
	out := clientObservation(classifier.TCPFlagSYN, 100, 0, 4096, now)
	out.VisibilityComplete = false
	store.ObserveOutgoing(incomplete, 25, out)
	in := serverObservation(classifier.TCPFlagSYN|classifier.TCPFlagACK, 1000, 101, 4096, 52, 0, now.Add(time.Millisecond))
	in.VisibilityComplete = false
	_, _ = store.ObserveIncoming("192.0.2.5", "203.0.113.10", 52004, 443, 25, in)
	rstIncomplete := serverObservation(classifier.TCPFlagRST, 9000, 0, 0, 30, 0, now.Add(2*time.Millisecond))
	rstIncomplete.VisibilityComplete = false
	evidence, _ = store.ObserveIncoming("192.0.2.5", "203.0.113.10", 52004, 443, 25, rstIncomplete)
	if result := store.Enforce(cfg, evidence); result.Decision != PassiveRSTDecisionFailOpen {
		t.Fatalf("incomplete visibility result=%+v", result)
	}
}

func TestPassiveRSTScopeBudgetsAndNonSlidingWindowAreBounded(t *testing.T) {
	now := time.Unix(2300, 0).UTC()
	clk := clock.NewFixed(now)
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clk)
	flow := passiveRSTTestFlow(6, 52005)
	establishPassiveRSTFlow(t, store, flow, 26, now, false)
	cfg := activePassiveRSTConfig(config.PassiveRSTConservative)
	cfg.SuppressionBudgetPerFlow = 2

	for i := 0; i < 2; i++ {
		evidence := forgedPassiveRSTEvidence(t, store, flow, 26, clk.Now().Add(time.Duration(i+1)*time.Millisecond))
		if result := store.Enforce(cfg, evidence); !result.Suppress() {
			t.Fatalf("suppression %d result=%+v", i, result)
		}
	}
	evidence := forgedPassiveRSTEvidence(t, store, flow, 26, clk.Now().Add(3*time.Millisecond))
	if result := store.Enforce(cfg, evidence); result.Decision != PassiveRSTDecisionFailOpen || result.BudgetRemaining != 0 {
		t.Fatalf("budget result=%+v", result)
	}

	flow2 := passiveRSTTestFlow(7, 52006)
	establishPassiveRSTFlow(t, store, flow2, 26, now, false)
	evidence = forgedPassiveRSTEvidence(t, store, flow2, 26, now.Add(4*time.Millisecond))
	first := store.Enforce(cfg, evidence)
	if !first.Suppress() {
		t.Fatalf("first window result=%+v", first)
	}
	clk.Advance(6 * time.Second)
	evidence = forgedPassiveRSTEvidence(t, store, flow2, 26, clk.Now())
	result := store.Enforce(cfg, evidence)
	if result.Decision != PassiveRSTDecisionFailOpen || result.Reason != "non-sliding suppression window expired" || !result.SuppressionExpiresAt.Equal(first.SuppressionExpiresAt) {
		t.Fatalf("non-sliding result=%+v first=%+v", result, first)
	}
}

func TestPassiveRSTAggressiveRequiresExplicitConfirmationAndRouteStability(t *testing.T) {
	now := time.Unix(2400, 0).UTC()
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))
	flow := passiveRSTTestFlow(8, 52007)
	establishPassiveRSTFlow(t, store, flow, 27, now, false)
	evidence := forgedPassiveRSTEvidence(t, store, flow, 27, now.Add(50*time.Millisecond))
	cfg := activePassiveRSTConfig(config.PassiveRSTAggressive)
	if result := store.Enforce(cfg, evidence); result.Decision != PassiveRSTDecisionFailOpen {
		t.Fatalf("unconfirmed aggressive result=%+v", result)
	}
	cfg.AggressiveConfirmationToken = config.PassiveRSTAggressiveConfirmation
	if result := store.Enforce(cfg, evidence); !result.Suppress() || result.EffectiveMode != config.PassiveRSTAggressive {
		t.Fatalf("confirmed aggressive result=%+v", result)
	}
}

func TestPassiveRSTUnknownFlowNeverSuppresses(t *testing.T) {
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(time.Unix(2500, 0).UTC()))
	flow := passiveRSTTestFlow(9, 52008)
	evidence := PassiveRSTEvidence{ObservedAt: time.Unix(2500, 0).UTC(), Flow: PassiveRSTFlowSnapshot{FlowKey: flow, ConfigGeneration: 28, SetID: "youtube", DeviceScope: "aa:bb:cc:dd:ee:01", VisibilityComplete: true, SYNSeen: true, SYNACKSeen: true}, Sequence: PassiveRSTWindowDecision{Reliable: true, InWindow: false}, Signals: []PassiveRSTSignalObservation{{Signal: PassiveRSTSignalSequenceOutside, Strength: PassiveRSTStrengthStrong}}}
	if result := store.Enforce(activePassiveRSTConfig(config.PassiveRSTConservative), evidence); result.Decision != PassiveRSTDecisionFailOpen {
		t.Fatalf("unknown flow result=%+v", result)
	}
}

func TestPassiveRSTScopeAndGlobalBudgetFailOpen(t *testing.T) {
	now := time.Unix(2600, 0).UTC()
	clk := clock.NewFixed(now)
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clk)
	flow := passiveRSTTestFlow(10, 52009)
	establishPassiveRSTFlow(t, store, flow, 29, now, false)
	evidence := forgedPassiveRSTEvidence(t, store, flow, 29, now.Add(time.Millisecond))
	cfg := activePassiveRSTConfig(config.PassiveRSTConservative)
	cfg.DeviceScopes = []string{"aa:bb:cc:dd:ee:ff"}
	if result := store.Enforce(cfg, evidence); result.Decision != PassiveRSTDecisionFailOpen {
		t.Fatalf("scope mismatch result=%+v", result)
	}

	cfg.DeviceScopes = []string{"aa:bb:cc:dd:ee:01"}
	cfg.GlobalSuppressionsPerMinute = 1
	if result := store.Enforce(cfg, evidence); !result.Suppress() {
		t.Fatalf("first global budget result=%+v", result)
	}
	flow2 := passiveRSTTestFlow(11, 52010)
	establishPassiveRSTFlow(t, store, flow2, 29, now, false)
	evidence2 := forgedPassiveRSTEvidence(t, store, flow2, 29, now.Add(2*time.Millisecond))
	if result := store.Enforce(cfg, evidence2); result.Decision != PassiveRSTDecisionFailOpen || result.Reason != "global suppression rate budget exhausted" {
		t.Fatalf("global budget result=%+v", result)
	}
}

func TestPassiveRSTAggressiveFailsOpenOnRouteChangeSuspicion(t *testing.T) {
	now := time.Unix(2700, 0).UTC()
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))
	flow := passiveRSTTestFlow(12, 52011)
	establishPassiveRSTFlow(t, store, flow, 30, now, false)
	evidence := forgedPassiveRSTEvidence(t, store, flow, 30, now.Add(time.Millisecond))
	evidence.Baseline.Quality = PassiveRSTBaselineRouteChangeSuspected
	cfg := activePassiveRSTConfig(config.PassiveRSTAggressive)
	cfg.AggressiveConfirmationToken = config.PassiveRSTAggressiveConfirmation
	if result := store.Enforce(cfg, evidence); result.Decision != PassiveRSTDecisionFailOpen || result.Reason != "route change suspected" {
		t.Fatalf("route-change aggressive result=%+v", result)
	}
}
