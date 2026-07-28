package runtimecontrol

import (
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func scopedConfigs() (*config.Config, *config.Config) {
	active := config.NewConfig()
	first := config.NewSetConfig()
	first.Id = "youtube-api"
	first.Name = "api"
	second := config.NewSetConfig()
	second.Id = "youtube-video"
	second.Name = "video"
	active.Sets = []*config.SetConfig{&first, &second}
	candidate := active.CloneForRuntimeUpdate()
	candidate.GetSetById("youtube-api").TCP.SynFake = true
	candidate.System.Classifier.Flags.TransactionalApplyEnabled = true
	return &active, candidate
}

func TestValidateLiveCandidateScopeAllowsRequestedSetAndClassifier(t *testing.T) {
	active, candidate := scopedConfigs()
	if err := ValidateLiveCandidateScope(active, candidate, "youtube-api"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateLiveCandidateScopeRejectsUnscopedChange(t *testing.T) {
	active, candidate := scopedConfigs()
	candidate.GetSetById("youtube-video").TCP.SynFake = true
	err := ValidateLiveCandidateScope(active, candidate, "youtube-api")
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("unexpected error: %v", err)
	}
}
