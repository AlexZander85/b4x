package config

import "testing"

func TestMigratePPEProductDefaultsPreservesMonitoringMode(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = ""
	cfg.System.Classifier.Runtime.Capture.PPE = PPEOffloadConfig{}
	if err := migratePPEProductDefaults(cfg); err != nil {
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

func TestMigratePPEProductDefaultsRejectsLegacyGlobalMode(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.Capture.OffloadPolicy = OffloadPolicyDisableGlobal
	if err := migratePPEProductDefaults(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.System.Classifier.Runtime.Capture.OffloadPolicy != OffloadPolicyDetect {
		t.Fatal("global offload mode must not be enabled by migration")
	}
}
