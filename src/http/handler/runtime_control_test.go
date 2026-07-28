package handler

import (
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func runtimeControlTestConfig() *config.Config {
	cfg := config.NewConfig()
	cfg.System.Classifier.Flags.TransactionalApplyEnabled = true
	set := config.NewSetConfig()
	set.Id = "youtube-api"
	set.Name = "API"
	cfg.Sets = []*config.SetConfig{&set}
	return &cfg
}

func TestRuntimeControlDiffAllowsClassifierAndSetChanges(t *testing.T) {
	active := runtimeControlTestConfig()
	candidate := active.CloneForRuntimeUpdate()
	candidate.System.Classifier.Confidence.Mutate++
	candidate.GetSetById("youtube-api").TCP.SynFake = true
	if err := runtimeControlDiffAllowed(active, candidate); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeControlDiffRejectsKernelEnvelopeChange(t *testing.T) {
	active := runtimeControlTestConfig()
	candidate := active.CloneForRuntimeUpdate()
	candidate.GetSetById("youtube-api").TCP.DPortFilter = "8443"
	if err := runtimeControlDiffAllowed(active, candidate); err == nil || !strings.Contains(err.Error(), "capture port envelope") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuntimeControlDiffRejectsUnrelatedConfig(t *testing.T) {
	active := runtimeControlTestConfig()
	candidate := active.CloneForRuntimeUpdate()
	candidate.System.Logging.Level++
	if err := runtimeControlDiffAllowed(active, candidate); err == nil || !strings.Contains(err.Error(), "only permits") {
		t.Fatalf("unexpected error: %v", err)
	}
}
