package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSaveToHistoryPersistsCanceledSuite guards the G-2 field requirement:
// a canceled suite must still persist whatever evidence it gathered —
// partial results must not be lost on DELETE /api/discovery/cancel/{id}.
func TestSaveToHistoryPersistsCanceledSuite(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "b4.json")

	suite := &CheckSuite{
		Id:        "canceled-suite-1",
		Status:    CheckStatusCanceled,
		StartTime: time.Now().Add(-2 * time.Minute),
		EndTime:   time.Now(),
		DomainDiscoveryResults: map[string]*DomainDiscoveryResult{
			"example.com": {
				Domain:      "example.com",
				Url:         "https://example.com",
				BestPreset:  "desync-full-ttl5-c2",
				BestSpeed:   4299000,
				BestSuccess: true,
				Results: map[string]*DomainPresetResult{
					"desync-full-ttl5-c2": {
						PresetName: "desync-full-ttl5-c2",
						Family:     FamilyDesync,
						Status:     CheckStatusComplete,
						Speed:      4299000,
					},
				},
			},
		},
	}

	SaveToHistory(suite, cfgPath)

	history := LoadDiscoveryHistory(cfgPath)
	if len(history.Entries) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(history.Entries))
	}
	e := history.Entries[0]
	if e.Domain != "example.com" {
		t.Errorf("unexpected domain %q", e.Domain)
	}
	if e.Status != CheckStatusCanceled {
		t.Errorf("expected status %q, got %q", CheckStatusCanceled, e.Status)
	}
	if !e.BestSuccess {
		t.Error("expected best_success to be preserved for canceled suite")
	}
	if e.BestPreset != "desync-full-ttl5-c2" {
		t.Errorf("expected best_preset preserved, got %q", e.BestPreset)
	}
	if len(e.Results) != 1 {
		t.Errorf("expected per-preset results preserved, got %d entries", len(e.Results))
	}
}

// TestCanceledSuiteSkipsHistoryWithoutResults ensures a canceled suite that
// gathered nothing does not create noise entries in history.
func TestCanceledSuiteSkipsHistoryWithoutResults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "b4.json")

	suite := &CheckSuite{
		Id:        "canceled-suite-2",
		Status:    CheckStatusCanceled,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}

	SaveToHistory(suite, cfgPath)

	history := LoadDiscoveryHistory(cfgPath)
	if len(history.Entries) != 0 {
		t.Fatalf("expected no history entries, got %d", len(history.Entries))
	}
	_ = os.Remove(cfgPath) // silence unused import guard
}
