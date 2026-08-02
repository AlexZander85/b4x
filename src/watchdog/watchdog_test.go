package watchdog

import (
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

// FB-28 cutover: the legacy mutating path (applyBatchResults, applyGroup,
// groupByConfig, configsMatch, domainWithSet, setListsAnyDomain,
// domainInSNIList) was removed from the production code. These tests assert
// the state that remains: read-only domain matching helpers used only for
// status projection, and the absence of any config-mutation capability on
// the Watchdog.

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"youtube.com", "youtube.com"},
		{"https://youtube.com", "youtube.com"},
		{"https://youtube.com/watch?v=123", "youtube.com"},
		{"http://example.com:8080/path", "example.com"},
		{"example.com/path", "example.com"},
		{"example.com:443", "example.com"},
		{"example.com?query=1", "example.com"},
		{"https://www.roblox.com/", "www.roblox.com"},
		{"  https://discord.com  ", "discord.com"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ExtractDomain(tt.input)
			if result != tt.expected {
				t.Errorf("ExtractDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSyncDomainStates(t *testing.T) {
	w := &Watchdog{
		domainStates: map[string]*DomainStatus{
			"old.com": {Domain: "old.com", Status: StatusHealthy},
			"keep.com": {Domain: "keep.com", Status: StatusDegraded, ConsecutiveFailures: 2},
		},
	}

	wdCfg := config.WatchdogConfig{
		Domains:     []string{"keep.com", "new.com"},
		IntervalSec: 300,
	}

	w.syncDomainStates(wdCfg)

	if _, ok := w.domainStates["old.com"]; ok {
		t.Error("old.com should have been removed")
	}

	if st := w.domainStates["keep.com"]; st == nil {
		t.Fatal("keep.com should still exist")
	} else if st.ConsecutiveFailures != 2 {
		t.Error("keep.com state should be preserved")
	}

	if st := w.domainStates["new.com"]; st == nil {
		t.Fatal("new.com should have been created")
	} else if st.Status != StatusHealthy {
		t.Errorf("new.com should be healthy, got %s", st.Status)
	} else if st.Interval != 300 {
		t.Errorf("new.com interval should be 300, got %d", st.Interval)
	}
}

// TestWatchdogNoSaveFunc pins the FB-28 cutover: Watchdog.New takes no
// config save callback (compile-time invariant: two arguments), and a
// freshly constructed Watchdog carries no persistence callback. The operator
// HTTP API (http/handler saveAndPushConfig) is the only mutating save path.
func TestWatchdogNoSaveFunc(t *testing.T) {
	cfg := config.NewConfig()
	var ptr atomic.Pointer[config.Config]
	ptr.Store(&cfg)

	w := New(&ptr, nil)
	if w == nil {
		t.Fatal("New must return a Watchdog")
	}

	// FB-28 cutover invariant: the Watchdog type must not carry a config
	// save callback (passive observation never persists configuration).
	// Reflection is the only way to assert the absence of a struct field.
	if _, ok := reflect.TypeOf(Watchdog{}).FieldByName("saveFunc"); ok {
		t.Fatal("Watchdog must have no saveFunc field after FB-28 cutover")
	}

	// GetState is read-only projection: it must not panic and must not
	// mutate or persist configuration.
	state := w.GetState()
	if state.Domains == nil || len(state.Domains) != 0 {
		t.Fatalf("fresh config watchdog must project no domains, got %+v", state)
	}
}

func TestSetContainsAnyDomain(t *testing.T) {
	set := &config.SetConfig{}
	set.Targets.SNIDomains = []string{"youtube.com", "discord.com"}

	t.Run("exact match", func(t *testing.T) {
		if !setContainsAnyDomain(set, []string{"youtube.com"}) {
			t.Error("should match exact domain")
		}
	})

	t.Run("no match", func(t *testing.T) {
		if setContainsAnyDomain(set, []string{"twitter.com"}) {
			t.Error("should not match unrelated domain")
		}
	})

	t.Run("subdomain match", func(t *testing.T) {
		if !setContainsAnyDomain(set, []string{"www.youtube.com"}) {
			t.Error("should match subdomain")
		}
	})

	t.Run("reverse subdomain match", func(t *testing.T) {
		setWww := &config.SetConfig{}
		setWww.Targets.SNIDomains = []string{"www.discord.com"}
		if !setContainsAnyDomain(setWww, []string{"discord.com"}) {
			t.Error("should match parent domain")
		}
	})

	t.Run("partial name no match", func(t *testing.T) {
		if setContainsAnyDomain(set, []string{"cord.com"}) {
			t.Error("cord.com should not match discord.com")
		}
	})

	t.Run("uses DomainsToMatch when available", func(t *testing.T) {
		setGeo := &config.SetConfig{}
		setGeo.Targets.SNIDomains = []string{"youtube.com"}
		setGeo.Targets.DomainsToMatch = []string{"youtube.com", "googlevideo.com", "ytimg.com"}
		if !setContainsAnyDomain(setGeo, []string{"googlevideo.com"}) {
			t.Error("should match via DomainsToMatch")
		}
	})

	t.Run("case-insensitive query", func(t *testing.T) {
		if !setContainsAnyDomain(set, []string{"YouTube.com"}) {
			t.Error("should match regardless of case")
		}
	})

	t.Run("whitespace trimmed query", func(t *testing.T) {
		if !setContainsAnyDomain(set, []string{"  youtube.com  "}) {
			t.Error("should match after trimming whitespace")
		}
	})

	t.Run("case-insensitive stored domain", func(t *testing.T) {
		mixed := &config.SetConfig{}
		mixed.Targets.SNIDomains = []string{"YouTube.COM"}
		if !setContainsAnyDomain(mixed, []string{"youtube.com"}) {
			t.Error("should match a mixed-case stored domain")
		}
	})
}

func TestDomainMatchesSuffix(t *testing.T) {
	tests := []struct {
		domain, target string
		expected       bool
	}{
		{"www.youtube.com", "youtube.com", true},
		{"youtube.com", "www.youtube.com", true},
		{"youtube.com", "youtube.com", false},
		{"cord.com", "discord.com", false},
		{"evil-youtube.com", "youtube.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.domain+"_"+tt.target, func(t *testing.T) {
			if domainMatchesSuffix(tt.domain, tt.target) != tt.expected {
				t.Errorf("domainMatchesSuffix(%q, %q) = %v, want %v",
					tt.domain, tt.target, !tt.expected, tt.expected)
			}
		})
	}
}

// The legacy mutating helpers (applyGroup, groupByConfig, configsMatch,
// domainWithSet, setListsAnyDomain, domainInSNIList) were removed by the
// FB-28 cutover; their tests went with them. Tests covering the remaining
// read-only projection helpers (setContainsAnyDomain, domainMatchesSuffix)
// are above; nothing below may reference a mutating symbol.
