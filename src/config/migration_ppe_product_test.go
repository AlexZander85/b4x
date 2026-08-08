package config

import (
	"path/filepath"
	"testing"
)

func TestMigratePPEProductDefaultsPreservesMonitoringMode(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = ""
	cfg.System.Classifier.Runtime.Capture.PPE = PPEOffloadConfig{}
	if err := migratePPEProductDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	capture := cfg.System.Classifier.Runtime.Capture
	if capture.OffloadPolicy != OffloadPolicyDetect {
		t.Fatalf("migration enabled mutation policy: %q", capture.OffloadPolicy)
	}
	if capture.PPE.ConnskipPackets <= 0 || len(capture.PPE.TCPPorts) == 0 {
		t.Fatalf("PPE defaults were not restored: %+v", capture.PPE)
	}
}

func TestMigratePPEProductDefaultsMarksExistingInstallation(t *testing.T) {
	cfg := NewConfig()
	if err := migratePPEProductDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.System.Classifier.Runtime.Capture.OffloadPolicyUserChosen {
		t.Error("existing installation must be marked user-chosen so auto-enable (FB-21) never flips it")
	}
}

func TestFreshInstallationStaysAutoEligible(t *testing.T) {
	// A brand-new config (no file, no migration) has no user-chosen marker:
	// the fresh Keenetic NDM + MediaTek auto-enable path is eligible.
	cfg := NewConfig()
	if cfg.System.Classifier.Runtime.Capture.OffloadPolicyUserChosen {
		t.Error("fresh installation must default to auto-eligible (marker false)")
	}
	if cfg.System.Classifier.Runtime.Capture.OffloadPolicy != OffloadPolicyDetect {
		t.Errorf("fresh installation policy = %q, want detect", cfg.System.Classifier.Runtime.Capture.OffloadPolicy)
	}
}

func TestOffloadPolicyUserChosenSurvivesRoundtrip(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = OffloadPolicyExclude
	cfg.System.Classifier.Runtime.Capture.OffloadPolicyUserChosen = true

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := cfg.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	loaded := NewConfig()
	if err := loaded.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if !loaded.System.Classifier.Runtime.Capture.OffloadPolicyUserChosen {
		t.Error("user-chosen provenance must survive a file roundtrip")
	}
	if loaded.System.Classifier.Runtime.Capture.OffloadPolicy != OffloadPolicyExclude {
		t.Errorf("policy = %q, want exclude", loaded.System.Classifier.Runtime.Capture.OffloadPolicy)
	}
}

func TestMigratePPEProductDefaultsRejectsLegacyGlobalMode(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = OffloadPolicyDisableGlobal
	if err := migratePPEProductDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.System.Classifier.Runtime.Capture.OffloadPolicy != OffloadPolicyDetect {
		t.Fatal("global offload mode must not be enabled by migration")
	}
}
