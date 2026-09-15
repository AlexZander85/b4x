package transportwg

import "testing"

func TestProtonDefaultsToImmediateEndpointCooldown(t *testing.T) {
	cfg := SeekerConfig{Target: TargetProton}
	cfg.fillDefaults()
	if cfg.StrikesToCooldown != 1 {
		t.Fatalf("proton strikes=%d want 1", cfg.StrikesToCooldown)
	}
}

func TestNonProtonKeepsSharedTwoStrikeDefault(t *testing.T) {
	cfg := SeekerConfig{Target: TargetCfWarp}
	cfg.fillDefaults()
	if cfg.StrikesToCooldown != DefaultSeekStrikes {
		t.Fatalf("cf-warp strikes=%d want %d", cfg.StrikesToCooldown, DefaultSeekStrikes)
	}
}

func TestExplicitStrikePolicyIsPreserved(t *testing.T) {
	cfg := SeekerConfig{Target: TargetProton, StrikesToCooldown: 3}
	cfg.fillDefaults()
	if cfg.StrikesToCooldown != 3 {
		t.Fatalf("explicit proton strikes=%d want 3", cfg.StrikesToCooldown)
	}
}
