package handler

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/crossservice"
	"github.com/daniellavrushin/b4/observability"
)

const classifierIsolationAPIPath = "/api/v2/classifier/isolation"

type classifierIsolationSetStatus struct {
	SetID             string              `json:"set_id"`
	DomainOnly        bool                `json:"domain_only"`
	ConfiguredPolicy  config.DomainPolicy `json:"configured_policy"`
	EffectivePolicy   config.DomainPolicy `json:"effective_policy"`
	UnsafeLegacy      bool                `json:"unsafe_legacy"`
	MigrationRequired bool                `json:"migration_required"`
	MigrationTarget   config.DomainPolicy `json:"migration_target,omitempty"`
	ReasonCode        string              `json:"reason_code,omitempty"`
}

type classifierNegativeControlStatus struct {
	Status                      string    `json:"status"`
	ReportGeneration            string    `json:"report_generation,omitempty"`
	CheckedAt                   time.Time `json:"checked_at,omitempty"`
	RequiredScenarios           int       `json:"required_scenarios,omitempty"`
	PassedScenarios             int       `json:"passed_scenarios,omitempty"`
	UnrelatedControlActionTotal uint64    `json:"unrelated_control_action_total"`
	CrossServiceCacheReuse      uint64    `json:"cross_service_cache_reuse"`
	CrossServiceRouteReuse      uint64    `json:"cross_service_route_reuse"`
	PromotionAllowed            bool      `json:"promotion_allowed"`
	Reason                      string    `json:"reason,omitempty"`
}

type classifierIsolationStatus struct {
	APIVersion       string                          `json:"api_version"`
	GeneratedAt      time.Time                       `json:"generated_at"`
	ConfigGeneration string                          `json:"config_generation,omitempty"`
	Sets             []classifierIsolationSetStatus  `json:"sets"`
	Metrics          []observability.MetricSample    `json:"metrics"`
	RecentEvents     []observability.TraceEvent      `json:"recent_events,omitempty"`
	Warnings         []string                        `json:"warnings,omitempty"`
	NegativeControl  classifierNegativeControlStatus `json:"negative_control"`
	RawHostnames     bool                            `json:"raw_hostnames"`
}

func (api *API) handleClassifierIsolation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	report, _ := crossservice.Default().Latest()
	sendResponse(w, buildClassifierIsolationStatus(api.getCfg(), observability.Default(), &report, time.Now().UTC()))
}

func buildClassifierIsolationStatus(cfg *config.Config, recorder *observability.Recorder, report *crossservice.ValidationReport, now time.Time) classifierIsolationStatus {
	status := classifierIsolationStatus{
		APIVersion:   config.ClassifierAPIV23,
		GeneratedAt:  now,
		Sets:         make([]classifierIsolationSetStatus, 0),
		Metrics:      make([]observability.MetricSample, 0),
		RawHostnames: false,
		NegativeControl: classifierNegativeControlStatus{
			Status: "not_run", PromotionAllowed: false,
			Reason: "Gmail/Google negative-control validation has not produced an acceptance report",
		},
	}
	if cfg != nil {
		status.ConfigGeneration = cfg.RuntimeGeneration
		migration := make(map[string]config.DomainPolicyMigrationPreview)
		for _, preview := range cfg.PreviewDomainPolicyMigration() {
			migration[preview.SetID] = preview
		}
		for _, set := range cfg.Sets {
			if set == nil {
				continue
			}
			configured := config.NormalizeDomainPolicy(set.Targets.DomainPolicy)
			redactedSetID := observability.RedactIdentifier(set.Id)
			item := classifierIsolationSetStatus{
				SetID: redactedSetID, DomainOnly: set.Targets.DomainOnly, ConfiguredPolicy: configured,
				EffectivePolicy: cfg.EffectiveDomainPolicy(set), UnsafeLegacy: config.UnsafeLegacyDomainScope(cfg, set),
			}
			if preview, ok := migration[set.Id]; ok {
				item.MigrationRequired = preview.Required
				item.MigrationTarget = preview.To
				item.ReasonCode = preview.ReasonCode
			}
			if item.UnsafeLegacy {
				status.Warnings = append(status.Warnings, config.UnsafeLegacyDomainScopeReason+":"+redactedSetID)
			}
			status.Sets = append(status.Sets, item)
		}
	}
	sort.Slice(status.Sets, func(i, j int) bool { return status.Sets[i].SetID < status.Sets[j].SetID })

	hasReport := report != nil && report.SchemaVersion != ""
	if hasReport {
		status.NegativeControl.ReportGeneration = report.Generation
		status.NegativeControl.CheckedAt = report.CheckedAt
		status.NegativeControl.RequiredScenarios = report.RequiredScenarios
		status.NegativeControl.PassedScenarios = report.PassedScenarios
		status.NegativeControl.UnrelatedControlActionTotal = report.UnrelatedControlActionTotal
		status.NegativeControl.CrossServiceCacheReuse = report.CrossServiceCacheReuse
		status.NegativeControl.CrossServiceRouteReuse = report.CrossServiceRouteReuse
		status.NegativeControl.PromotionAllowed = report.PromotionAllowed
		if report.Passed {
			status.NegativeControl.Status = "passed"
			status.NegativeControl.Reason = "all required negative-control hard gates passed"
		} else {
			status.NegativeControl.Status = "failed"
			status.NegativeControl.Reason = "negative-control report contains hard-gate failures"
		}
	}
	if recorder == nil {
		return status
	}
	wanted := map[string]struct{}{
		observability.MetricCrossServiceCandidate: {}, observability.MetricCrossServiceRevoked: {},
		observability.MetricCrossServiceAmbiguous: {}, observability.MetricDomainAuthorization: {},
		observability.MetricLegacyScopeRejected: {}, observability.MetricBlockedCacheWrite: {},
		observability.MetricRouteBinding: {}, observability.MetricQUICScopeRejected: {},
		observability.MetricUnrelatedControlAction: {},
	}
	metrics := recorder.Metrics.Snapshot(now)
	for _, sample := range metrics.Counters {
		if _, ok := wanted[sample.Name]; !ok {
			continue
		}
		status.Metrics = append(status.Metrics, sample)
		if sample.Name == observability.MetricUnrelatedControlAction && !hasReport {
			status.NegativeControl.UnrelatedControlActionTotal += sample.Value
		}
	}
	if !hasReport && status.NegativeControl.UnrelatedControlActionTotal > 0 {
		status.NegativeControl.Status = "failed"
		status.NegativeControl.Reason = "unrelated service received a service-scoped action"
	}

	allowedKinds := map[string]struct{}{
		"capture_candidate_disposition": {}, "action_authorization": {}, "quic_action_authorization": {},
		"route_binding": {}, "route_binding_result": {}, "scoped_failure_state": {},
	}
	for _, event := range recorder.Trace.Snapshot() {
		if _, ok := allowedKinds[event.Kind]; ok {
			status.RecentEvents = append(status.RecentEvents, event)
		}
	}
	if len(status.RecentEvents) > 64 {
		status.RecentEvents = append([]observability.TraceEvent(nil), status.RecentEvents[len(status.RecentEvents)-64:]...)
	}
	status.Warnings = compactStrings(status.Warnings)
	for i := range status.Warnings {
		status.Warnings[i] = strings.TrimSpace(status.Warnings[i])
	}
	return status
}
