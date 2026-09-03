package crossservice

import (
	"errors"
	"testing"
	"time"
)

func passingInput(generation string) ValidationInput {
	domain := HashDomain("observed.example")
	baseline := []FlowResult{
		{FlowID: "base-gmail", Service: ServiceGmail, Role: RoleControl, Milestone: "body-content", DomainHash: domain, Provenance: "dns+sni", ConfigGeneration: "baseline", Success: true, DurationMillis: 100},
		{FlowID: "base-feed", Service: ServiceGoogleFeed, Role: RoleControl, Milestone: "feed-refresh", DomainHash: domain, Provenance: "dns+quic", ConfigGeneration: "baseline", Success: true, DurationMillis: 100},
	}
	candidate := []FlowResult{
		{FlowID: "gmail", Service: ServiceGmail, Role: RoleControl, Milestone: "body-content", DomainHash: domain, Provenance: "dns+sni", ConfigGeneration: generation, Success: true, DurationMillis: 105},
		{FlowID: "feed", Service: ServiceGoogleFeed, Role: RoleControl, Milestone: "feed-refresh", DomainHash: domain, Provenance: "dns+quic", ConfigGeneration: generation, Success: true, DurationMillis: 110},
		{FlowID: "yt-api", Service: ServiceYouTube, Role: RoleTarget, Milestone: "api-load", TargetClass: TargetClassAPI, DomainHash: domain, Provenance: "sni", ConfigGeneration: generation, Success: true, DurationMillis: 80},
		{FlowID: "yt-ui", Service: ServiceYouTube, Role: RoleTarget, Milestone: "ui-load", TargetClass: TargetClassUI, DomainHash: domain, Provenance: "reassembled-sni", ConfigGeneration: generation, Success: true, DurationMillis: 90},
		{FlowID: "yt-video", Service: ServiceYouTube, Role: RoleTarget, Milestone: "video-start", TargetClass: TargetClassVideo, DomainHash: domain, Provenance: "quic-sni", ConfigGeneration: generation, Success: true, DurationMillis: 120},
	}
	scenarios := make([]ScenarioResult, 0, len(requiredScenarioIDs))
	for _, id := range requiredScenarioIDs {
		scenarios = append(scenarios, ScenarioResult{ID: id, Passed: true})
	}
	return ValidationInput{Generation: generation, TargetSetIDs: []string{"youtube-api", "youtube-ui", "youtube-video"}, Baseline: baseline, Candidate: candidate, Scenarios: scenarios, MaxLatencyRegressionPercent: 20}
}

func TestValidatePassingMatrixAllowsPromotion(t *testing.T) {
	now := time.Unix(100, 0)
	report := Validate(passingInput("generation-a"), now, time.Hour)
	if !report.Passed || !report.PromotionAllowed || report.PassedScenarios != len(requiredScenarioIDs) {
		t.Fatalf("report did not pass: %+v", report)
	}
	if report.UnrelatedControlActionTotal != 0 || report.CrossServiceCacheReuse != 0 || report.CrossServiceRouteReuse != 0 || report.RawHostnames {
		t.Fatalf("isolation counters/privacy invalid: %+v", report)
	}
}

func TestValidateRejectsYouTubeStateOnGmailSharedIPFlow(t *testing.T) {
	input := passingInput("generation-b")
	input.Candidate[0].Actions = []ScopedAction{{Kind: ActionIPBlockHit, SetID: "youtube-api", Scope: "client-domain-set-generation", Reused: true}}
	report := Validate(input, time.Now(), time.Hour)
	if report.Passed || report.PromotionAllowed || report.UnrelatedControlActionTotal != 1 || report.CrossServiceCacheReuse != 1 {
		t.Fatalf("cross-service contamination was not gated: %+v", report)
	}
}

func TestValidateRejectsRawDomainAndMissingScenario(t *testing.T) {
	input := passingInput("generation-c")
	input.Candidate[0].DomainHash = "mail.google.com"
	input.Scenarios = input.Scenarios[:len(input.Scenarios)-1]
	report := Validate(input, time.Now(), time.Hour)
	if report.Passed || len(report.HardGateFailures) < 2 {
		t.Fatalf("invalid report unexpectedly passed: %+v", report)
	}
}

func TestStoreRequiresFreshExactGenerationReport(t *testing.T) {
	now := time.Unix(200, 0)
	store := NewStore(2, time.Minute)
	report := store.ValidateAndStore(passingInput("generation-d"), now)
	if !report.Passed {
		t.Fatalf("report=%+v", report)
	}
	if err := store.RequirePromotion("generation-d", now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.RequirePromotion("other", now); !errors.Is(err, ErrValidationMissing) {
		t.Fatalf("missing report error=%v", err)
	}
	if err := store.RequirePromotion("generation-d", now.Add(2*time.Minute)); !errors.Is(err, ErrValidationExpired) {
		t.Fatalf("expired report error=%v", err)
	}
}
