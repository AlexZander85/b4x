package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	warp "github.com/daniellavrushin/b4/transport/warp"
)

func TestWarpDefaultsDisabled(t *testing.T) {
	cfg := NewConfig()
	if cfg.System.Warp.Enabled {
		t.Fatal("system.warp must be disabled by default (deploy discipline)")
	}
	if cfg.System.Warp.IdentityPath != DefaultWarpIdentityPath {
		t.Fatalf("default identity path = %q, want %q", cfg.System.Warp.IdentityPath, DefaultWarpIdentityPath)
	}
}

// Loading a JSON without a warp key unmarshals into the NewConfig receiver,
// so the defaults must survive (LoadFromFile does NOT apply ApplyConfigDefaults).
func TestWarpDefaultsSurviveJSONWithoutKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b4.json")
	if err := os.WriteFile(path, []byte(`{"system":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig()
	if err := cfg.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	if cfg.System.Warp.Enabled {
		t.Fatal("warp must stay disabled when the JSON has no warp key")
	}
	if cfg.System.Warp.IdentityPath != DefaultWarpIdentityPath {
		t.Fatalf("identity path = %q, want default preserved", cfg.System.Warp.IdentityPath)
	}
}

func TestEffectiveEndpointDefaultIsCatalogMember(t *testing.T) {
	var w WarpConfig
	ep, err := w.EffectiveEndpoint()
	if err != nil {
		t.Fatalf("default endpoint: %v", err)
	}
	if !warp.InCatalog(warp.KindMasqueH2, ep.Addr()) || !warp.KnownPort(ep.Port()) {
		t.Fatalf("default endpoint %s not a catalog member", ep)
	}
}

func TestEffectiveEndpointExplicitValues(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"catalog primary", "162.159.198.10:443", false},
		{"catalog alt port", "162.159.199.10:500", false},
		{"non-catalog address", "1.2.3.4:443", true},
		{"catalog address, foreign port", "162.159.198.10:1234", true},
		{"garbage", "not-an-endpoint", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := WarpConfig{Endpoint: tc.value}
			_, err := w.EffectiveEndpoint()
			if (err != nil) != tc.wantErr {
				t.Fatalf("endpoint %q: err=%v wantErr=%v", tc.value, err, tc.wantErr)
			}
		})
	}
}

func TestValidateWarpSection(t *testing.T) {
	t.Run("enabled requires absolute identity path", func(t *testing.T) {
		cfg := NewConfig()
		cfg.System.Warp.Enabled = true
		cfg.System.Warp.IdentityPath = "relative/path.json"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "identity_path") {
			t.Fatalf("want identity_path validation error, got %v", err)
		}
	})
	t.Run("disabled still validates explicit endpoint override", func(t *testing.T) {
		cfg := NewConfig()
		cfg.System.Warp.Endpoint = "1.2.3.4:443"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "endpoint") {
			t.Fatalf("want endpoint validation error even when disabled, got %v", err)
		}
	})
	t.Run("defaults pass", func(t *testing.T) {
		cfg := NewConfig()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("default config must validate clean: %v", err)
		}
	})
}
