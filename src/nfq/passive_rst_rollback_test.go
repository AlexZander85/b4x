package nfq

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
)

func rollbackPassiveRSTConfig() config.PassiveRSTRuntimeConfig {
	cfg := activePassiveRSTConfig(config.PassiveRSTConservative)
	cfg.RollbackWindowSeconds = 30
	cfg.ReconnectFailureThreshold = 2
	cfg.NoProgressThreshold = 2
	cfg.ControlFailureThreshold = 1
	cfg.QueueDropThreshold = 1
	cfg.RouterPressureThreshold = 1
	return cfg
}

func TestPassiveRSTRollbackIsExactScopeGenerationAndObserveOnly(t *testing.T) {
	now := time.Unix(3000, 0).UTC()
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))
	flow := passiveRSTTestFlow(1, 53000)
	establishPassiveRSTFlow(t, store, flow, 41, now, false)
	cfg := rollbackPassiveRSTConfig()

	if _, triggered := store.RecordHealth(cfg, PassiveRSTHealthSample{SetID: "youtube", DeviceScope: "aa:bb:cc:dd:ee:01", ConfigGeneration: 41, Environment: PassiveRSTEnvironmentProduction, ReconnectFailures: 1}); triggered {
		t.Fatal("rollback triggered before threshold")
	}
	rollback, triggered := store.RecordHealth(cfg, PassiveRSTHealthSample{SetID: "youtube", DeviceScope: "aa:bb:cc:dd:ee:01", ConfigGeneration: 41, Environment: PassiveRSTEnvironmentProduction, ReconnectFailures: 1})
	if !triggered || rollback.EffectiveMode != config.PassiveRSTObserve || rollback.Reason != "reconnect failure regression" {
		t.Fatalf("rollback=%+v triggered=%t", rollback, triggered)
	}
	evidence := forgedPassiveRSTEvidence(t, store, flow, 41, now.Add(time.Millisecond))
	result := store.Enforce(cfg, evidence)
	if result.Decision != PassiveRSTDecisionObserve || result.EffectiveMode != config.PassiveRSTObserve {
		t.Fatalf("rolled-back scope still enforced: %+v", result)
	}
	if recent := store.RecentRollbacks(2); len(recent) != 1 || recent[0].ConfigGeneration != 41 {
		t.Fatalf("recent rollbacks=%+v", recent)
	}
}

func TestPassiveRSTRollbackDoesNotCrossEnvironmentOrScope(t *testing.T) {
	now := time.Unix(3100, 0).UTC()
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))
	flow := passiveRSTTestFlow(2, 53001)
	establishPassiveRSTFlow(t, store, flow, 42, now, false)
	cfg := rollbackPassiveRSTConfig()
	candidate := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))
	candidate.SetEnvironment(PassiveRSTEnvironmentCandidate)
	if _, triggered := candidate.RecordHealth(cfg, PassiveRSTHealthSample{SetID: "youtube", DeviceScope: "aa:bb:cc:dd:ee:01", ConfigGeneration: 42, Environment: PassiveRSTEnvironmentCandidate, ControlFailures: 1}); !triggered {
		t.Fatal("candidate rollback was not recorded")
	}
	if _, triggered := store.RecordHealth(cfg, PassiveRSTHealthSample{SetID: "youtube", DeviceScope: "aa:bb:cc:dd:ee:01", ConfigGeneration: 42, Environment: PassiveRSTEnvironmentCandidate, ControlFailures: 1}); triggered {
		t.Fatal("candidate health was accepted by production store")
	}
	evidence := forgedPassiveRSTEvidence(t, store, flow, 42, now.Add(time.Millisecond))
	if result := store.Enforce(cfg, evidence); !result.Suppress() {
		t.Fatalf("candidate rollback leaked into production: %+v", result)
	}
	if removed := store.InvalidateGeneration(42); removed != 1 {
		t.Fatalf("generation cleanup removed=%d", removed)
	}
	if got := candidate.RecentRollbacks(4); len(got) != 1 {
		t.Fatalf("candidate audit history should remain bounded: %+v", got)
	}
	if got := store.RecentRollbacks(4); len(got) != 0 {
		t.Fatalf("candidate rollback leaked into production audit: %+v", got)
	}
}

func TestPassiveRSTRollbackWindowIsNonSlidingAndHardGatesTrigger(t *testing.T) {
	now := time.Unix(3200, 0).UTC()
	clk := clock.NewFixed(now)
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clk)
	cfg := rollbackPassiveRSTConfig()
	cfg.RollbackWindowSeconds = 5

	base := PassiveRSTHealthSample{SetID: "youtube", DeviceScope: "aa:bb:cc:dd:ee:01", ConfigGeneration: 43, Environment: PassiveRSTEnvironmentProduction}
	first := base
	first.NoProgress = 1
	if _, triggered := store.RecordHealth(cfg, first); triggered {
		t.Fatal("early no-progress rollback")
	}
	clk.Advance(6 * time.Second)
	if _, triggered := store.RecordHealth(cfg, first); triggered {
		t.Fatal("expired window became sliding")
	}
	queue := base
	queue.QueueDrops = 1
	rollback, triggered := store.RecordHealth(cfg, queue)
	if !triggered || rollback.Reason != "NFQUEUE drop regression" {
		t.Fatalf("hard-gate rollback=%+v triggered=%t", rollback, triggered)
	}
}
