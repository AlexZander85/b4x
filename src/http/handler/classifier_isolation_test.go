package handler

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/crossservice"
	"github.com/daniellavrushin/b4/observability"
)

func TestBuildClassifierIsolationStatusIsPrivacySafeAndExposesPolicy(t *testing.T) {
	cfg := config.DefaultConfig
	cfg.RuntimeGeneration = "generation-7"
	cfg.System.Classifier.DomainOnlyMode = config.DomainScopedHints
	cfg.Sets = []*config.SetConfig{{Id: "youtube-api", Targets: config.TargetsConfig{DomainOnly: true, DomainPolicy: config.DomainPolicyInherit}}}
	recorder := observability.NewRecorder()
	recorder.Trace.Record(observability.TraceEvent{Kind: "action_authorization", Fields: map[string]string{"domain": "mail.google.com", "set_id": "youtube-api"}})

	got := buildClassifierIsolationStatus(&cfg, recorder, nil, time.Unix(10, 0))
	if got.RawHostnames || len(got.Sets) != 1 || got.Sets[0].EffectivePolicy != config.DomainPolicyScopedHints {
		t.Fatalf("unexpected isolation status: %+v", got)
	}
	if len(got.RecentEvents) != 1 || got.RecentEvents[0].Fields["domain"] == "mail.google.com" {
		t.Fatalf("raw hostname leaked: %+v", got.RecentEvents)
	}
	if got.NegativeControl.Status != "not_run" || got.NegativeControl.PromotionAllowed {
		t.Fatalf("negative control must default closed: %+v", got.NegativeControl)
	}
}

func TestBuildClassifierIsolationStatusSurfacesUnrelatedControlFailure(t *testing.T) {
	recorder := observability.NewRecorder()
	recorder.Metrics.Inc(observability.MetricUnrelatedControlAction, map[string]string{"service": "gmail", "set": "youtube"}, 1)
	cfg := config.DefaultConfig
	got := buildClassifierIsolationStatus(&cfg, recorder, nil, time.Now())
	if got.NegativeControl.Status != "failed" || got.NegativeControl.UnrelatedControlActionTotal != 1 || got.NegativeControl.PromotionAllowed {
		t.Fatalf("negative control failure not exposed: %+v", got.NegativeControl)
	}
}

func TestBuildClassifierIsolationStatusUsesValidationReport(t *testing.T) {
	recorder := observability.NewRecorder()
	cfg := config.DefaultConfig
	report := crossservice.ValidationReport{
		SchemaVersion: crossservice.SchemaVersion, Generation: "candidate-generation", CheckedAt: time.Unix(20, 0),
		Passed: true, PromotionAllowed: true, RequiredScenarios: 14, PassedScenarios: 14,
	}
	got := buildClassifierIsolationStatus(&cfg, recorder, &report, time.Now())
	if got.NegativeControl.Status != "passed" || !got.NegativeControl.PromotionAllowed || got.NegativeControl.PassedScenarios != 14 {
		t.Fatalf("validation report not exposed: %+v", got.NegativeControl)
	}
}
