// Package crossservice validates that a service-scoped candidate does not leak
// authorization, action, failure, or routing state into unrelated services.
// It stores only bounded reports with hashed domains; packet payloads and raw
// hostnames are never retained.
package crossservice

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

const (
	SchemaVersion = "b4-cross-service-validation-v1"

	ServiceYouTube    = "youtube"
	ServiceGmail      = "gmail"
	ServiceGoogleFeed = "google-feed"

	RoleTarget  = "target"
	RoleControl = "control"

	TargetClassAPI   = "api"
	TargetClassUI    = "ui"
	TargetClassVideo = "video"
)

type ActionKind string

const (
	ActionAuthorization     ActionKind = "action_authorization"
	ActionToken             ActionKind = "action_token"
	ActionPacketMutation    ActionKind = "packet_mutation"
	ActionQUICReject        ActionKind = "quic_reject"
	ActionIPBlockHit        ActionKind = "ipblock_hit"
	ActionEscalation        ActionKind = "escalation"
	ActionRouteProxyBinding ActionKind = "route_proxy_binding"
	ActionPassiveRSTPolicy  ActionKind = "passive_rst_suppression"
)

const (
	ScenarioSameClientSequential    = "same-client-sequential-shared-ip"
	ScenarioSameClientConcurrent    = "same-client-concurrent"
	ScenarioTwoClientsSharedIP      = "two-clients-shared-ip"
	ScenarioStaticBeforeSNI         = "static-candidate-before-sni"
	ScenarioSplitReorderedHello     = "split-reordered-clienthello"
	ScenarioECHScopedHints          = "ech-scoped-hints"
	ScenarioLegacyLearnedIP         = "legacy-learned-ip"
	ScenarioIPBlockContamination    = "ipblock-contamination"
	ScenarioEscalationContamination = "escalation-contamination"
	ScenarioQUICFilterAll           = "quic-filter-all"
	ScenarioRouteProxyBinding       = "route-proxy-binding"
	ScenarioHotApplyRollback        = "hot-apply-rollback"
	ScenarioIPv4IPv6                = "ipv4-ipv6"
	ScenarioQueuePressure           = "queue-pressure-incomplete-visibility"
)

var requiredScenarioIDs = []string{
	ScenarioSameClientSequential,
	ScenarioSameClientConcurrent,
	ScenarioTwoClientsSharedIP,
	ScenarioStaticBeforeSNI,
	ScenarioSplitReorderedHello,
	ScenarioECHScopedHints,
	ScenarioLegacyLearnedIP,
	ScenarioIPBlockContamination,
	ScenarioEscalationContamination,
	ScenarioQUICFilterAll,
	ScenarioRouteProxyBinding,
	ScenarioHotApplyRollback,
	ScenarioIPv4IPv6,
	ScenarioQueuePressure,
}

var hardActionKinds = map[ActionKind]struct{}{
	ActionAuthorization: {}, ActionToken: {}, ActionPacketMutation: {}, ActionQUICReject: {},
	ActionIPBlockHit: {}, ActionEscalation: {}, ActionRouteProxyBinding: {}, ActionPassiveRSTPolicy: {},
}

type ScopedAction struct {
	Kind            ActionKind `json:"kind"`
	SetID           string     `json:"set_id"`
	AuthorizationID string     `json:"authorization_id,omitempty"`
	Scope           string     `json:"scope,omitempty"`
	Reused          bool       `json:"reused,omitempty"`
}

// FlowResult is accepted from a local/field controller. DomainHash must be a
// SHA-256-style hex digest produced from the actually observed DNS/SNI/QUIC
// hostname. Raw domains are rejected rather than copied into reports.
type FlowResult struct {
	FlowID           string         `json:"flow_id"`
	Service          string         `json:"service"`
	Role             string         `json:"role"`
	Milestone        string         `json:"milestone"`
	TargetClass      string         `json:"target_class,omitempty"`
	DomainHash       string         `json:"domain_hash"`
	Provenance       string         `json:"provenance"`
	ConfigGeneration string         `json:"config_generation"`
	Success          bool           `json:"success"`
	DurationMillis   uint64         `json:"duration_ms"`
	Actions          []ScopedAction `json:"actions,omitempty"`
}

type ScenarioResult struct {
	ID     string `json:"id"`
	Passed bool   `json:"passed"`
	Reason string `json:"reason,omitempty"`
}

type ValidationInput struct {
	Generation                  string           `json:"generation"`
	TargetSetIDs                []string         `json:"target_set_ids"`
	Baseline                    []FlowResult     `json:"baseline"`
	Candidate                   []FlowResult     `json:"candidate"`
	Scenarios                   []ScenarioResult `json:"scenarios"`
	MaxLatencyRegressionPercent float64          `json:"max_latency_regression_percent"`
	MaxLatencyRegressionMillis  uint64           `json:"max_latency_regression_ms"`
}

type HardGateViolation struct {
	Code       string `json:"code"`
	Service    string `json:"service,omitempty"`
	FlowID     string `json:"flow_id,omitempty"`
	SetID      string `json:"set_id,omitempty"`
	ActionKind string `json:"action_kind,omitempty"`
	Reason     string `json:"reason"`
}

type ValidationReport struct {
	SchemaVersion               string              `json:"schema_version"`
	Generation                  string              `json:"generation"`
	CheckedAt                   time.Time           `json:"checked_at"`
	ExpiresAt                   time.Time           `json:"expires_at"`
	Passed                      bool                `json:"passed"`
	PromotionAllowed            bool                `json:"promotion_allowed"`
	RequiredScenarios           int                 `json:"required_scenarios"`
	PassedScenarios             int                 `json:"passed_scenarios"`
	ControlFlows                int                 `json:"control_flows"`
	TargetFlows                 int                 `json:"target_flows"`
	UnrelatedControlActionTotal uint64              `json:"unrelated_control_action_total"`
	CrossServiceCacheReuse      uint64              `json:"cross_service_cache_reuse"`
	CrossServiceRouteReuse      uint64              `json:"cross_service_route_reuse"`
	HardGateFailures            []HardGateViolation `json:"hard_gate_failures,omitempty"`
	Warnings                    []string            `json:"warnings,omitempty"`
	RawHostnames                bool                `json:"raw_hostnames"`
}

func RequiredScenarioIDs() []string {
	return append([]string(nil), requiredScenarioIDs...)
}

func HashDomain(domain string) string {
	normalized := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func Validate(input ValidationInput, now time.Time, maxAge time.Duration) ValidationReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	report := ValidationReport{
		SchemaVersion: SchemaVersion, Generation: strings.TrimSpace(input.Generation), CheckedAt: now,
		ExpiresAt: now.Add(maxAge), RequiredScenarios: len(requiredScenarioIDs), RawHostnames: false,
	}
	addFailure := func(v HardGateViolation) {
		v.Service = sanitizeLabel(v.Service)
		v.FlowID = observability.RedactIdentifier(v.FlowID)
		v.SetID = observability.RedactIdentifier(v.SetID)
		v.Reason = limit(v.Reason, 192)
		report.HardGateFailures = append(report.HardGateFailures, v)
	}
	if report.Generation == "" {
		addFailure(HardGateViolation{Code: "generation_required", Reason: "candidate config generation is required"})
	}
	targetSets := make(map[string]struct{}, len(input.TargetSetIDs))
	for _, id := range input.TargetSetIDs {
		if id = strings.TrimSpace(id); id != "" {
			targetSets[id] = struct{}{}
		}
	}
	if len(targetSets) == 0 {
		addFailure(HardGateViolation{Code: "target_set_required", Reason: "at least one target service set ID is required"})
	}

	scenarioMap := make(map[string]ScenarioResult, len(input.Scenarios))
	for _, scenario := range input.Scenarios {
		id := strings.TrimSpace(scenario.ID)
		if id != "" {
			scenarioMap[id] = scenario
		}
	}
	for _, id := range requiredScenarioIDs {
		scenario, ok := scenarioMap[id]
		if !ok {
			addFailure(HardGateViolation{Code: "scenario_missing", Reason: "required scenario missing: " + id})
			continue
		}
		if !scenario.Passed {
			addFailure(HardGateViolation{Code: "scenario_failed", Reason: "required scenario failed: " + id})
			continue
		}
		report.PassedScenarios++
	}

	baseline := make(map[string]FlowResult, len(input.Baseline))
	for _, flow := range input.Baseline {
		if flow.Role == RoleControl {
			baseline[flowKey(flow)] = flow
		}
	}
	controlServices := map[string]bool{ServiceGmail: false, ServiceGoogleFeed: false}
	targetClasses := map[string]bool{TargetClassAPI: false, TargetClassUI: false, TargetClassVideo: false}
	latencyPercent := input.MaxLatencyRegressionPercent
	if latencyPercent < 0 || latencyPercent > 500 {
		addFailure(HardGateViolation{Code: "invalid_latency_budget", Reason: "latency regression percent must be between 0 and 500"})
		latencyPercent = 0
	}

	for _, flow := range input.Candidate {
		flow.Service = sanitizeLabel(flow.Service)
		flow.Role = strings.ToLower(strings.TrimSpace(flow.Role))
		if !validDomainHash(flow.DomainHash) {
			addFailure(HardGateViolation{Code: "raw_or_invalid_domain", Service: flow.Service, FlowID: flow.FlowID, Reason: "domain_hash must be a 16..128 character hexadecimal digest; raw hostnames are forbidden"})
		}
		if strings.TrimSpace(flow.Provenance) == "" {
			addFailure(HardGateViolation{Code: "provenance_required", Service: flow.Service, FlowID: flow.FlowID, Reason: "DNS/SNI/QUIC provenance is required"})
		}
		if flow.ConfigGeneration != report.Generation {
			addFailure(HardGateViolation{Code: "generation_mismatch", Service: flow.Service, FlowID: flow.FlowID, Reason: "flow config generation does not match validation generation"})
		}
		switch flow.Role {
		case RoleControl:
			report.ControlFlows++
			if _, ok := controlServices[flow.Service]; ok {
				controlServices[flow.Service] = true
			}
			if !flow.Success {
				addFailure(HardGateViolation{Code: "control_failed", Service: flow.Service, FlowID: flow.FlowID, Reason: "unrelated control milestone failed with candidate enabled"})
			}
			base, ok := baseline[flowKey(flow)]
			if !ok || !base.Success {
				addFailure(HardGateViolation{Code: "baseline_missing", Service: flow.Service, FlowID: flow.FlowID, Reason: "successful baseline milestone is required for comparison"})
			} else if exceedsLatencyBudget(base.DurationMillis, flow.DurationMillis, latencyPercent, input.MaxLatencyRegressionMillis) {
				addFailure(HardGateViolation{Code: "control_latency_regression", Service: flow.Service, FlowID: flow.FlowID, Reason: fmt.Sprintf("candidate duration %dms exceeds baseline %dms budget", flow.DurationMillis, base.DurationMillis)})
			}
			for _, action := range flow.Actions {
				if _, isHard := hardActionKinds[action.Kind]; !isHard {
					continue
				}
				if _, target := targetSets[strings.TrimSpace(action.SetID)]; !target {
					continue
				}
				report.UnrelatedControlActionTotal++
				if action.Reused && (action.Kind == ActionIPBlockHit || action.Kind == ActionEscalation || action.Kind == ActionPassiveRSTPolicy) {
					report.CrossServiceCacheReuse++
				}
				if action.Reused && action.Kind == ActionRouteProxyBinding {
					report.CrossServiceRouteReuse++
				}
				addFailure(HardGateViolation{Code: "unrelated_control_action", Service: flow.Service, FlowID: flow.FlowID, SetID: action.SetID, ActionKind: string(action.Kind), Reason: "unrelated control flow received target-service action or state"})
			}
		case RoleTarget:
			report.TargetFlows++
			if flow.Service != ServiceYouTube {
				addFailure(HardGateViolation{Code: "target_service_mismatch", Service: flow.Service, FlowID: flow.FlowID, Reason: "target role must identify the YouTube test cohort"})
			}
			if _, ok := targetClasses[flow.TargetClass]; ok && flow.Success {
				targetClasses[flow.TargetClass] = true
			}
			if !flow.Success {
				addFailure(HardGateViolation{Code: "target_failed", Service: flow.Service, FlowID: flow.FlowID, Reason: "expected target API/UI/video flow failed"})
			}
		default:
			addFailure(HardGateViolation{Code: "invalid_role", Service: flow.Service, FlowID: flow.FlowID, Reason: "flow role must be target or control"})
		}
	}
	for service, seen := range controlServices {
		if !seen {
			addFailure(HardGateViolation{Code: "control_service_missing", Service: service, Reason: "required negative-control service was not observed"})
		}
	}
	for class, seen := range targetClasses {
		if !seen {
			addFailure(HardGateViolation{Code: "target_class_missing", Service: ServiceYouTube, Reason: "successful target class missing: " + class})
		}
	}
	if report.UnrelatedControlActionTotal != 0 {
		report.Warnings = append(report.Warnings, "unrelated_control_action_total must be zero")
	}
	if report.CrossServiceCacheReuse != 0 {
		report.Warnings = append(report.Warnings, "cross-service cache reuse must be zero")
	}
	if report.CrossServiceRouteReuse != 0 {
		report.Warnings = append(report.Warnings, "cross-service route reuse must be zero")
	}
	sort.Slice(report.HardGateFailures, func(i, j int) bool {
		a, b := report.HardGateFailures[i], report.HardGateFailures[j]
		return a.Code+a.Service+a.FlowID < b.Code+b.Service+b.FlowID
	})
	report.Passed = len(report.HardGateFailures) == 0 && report.PassedScenarios == report.RequiredScenarios && report.UnrelatedControlActionTotal == 0 && report.CrossServiceCacheReuse == 0 && report.CrossServiceRouteReuse == 0
	report.PromotionAllowed = report.Passed
	return report
}

func flowKey(flow FlowResult) string {
	return sanitizeLabel(flow.Service) + "|" + strings.ToLower(strings.TrimSpace(flow.Milestone))
}

func validDomainHash(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func exceedsLatencyBudget(baseline, candidate uint64, percent float64, absolute uint64) bool {
	if baseline == 0 {
		return candidate > absolute
	}
	allowed := float64(baseline)*(1+percent/100) + float64(absolute)
	return float64(candidate) > allowed
}

func sanitizeLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return limit(b.String(), 64)
}

func limit(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}

var (
	ErrValidationMissing = errors.New("cross-service negative-control validation is missing")
	ErrValidationFailed  = errors.New("cross-service negative-control validation failed")
	ErrValidationExpired = errors.New("cross-service negative-control validation expired")
)

type Store struct {
	mu         sync.RWMutex
	maxReports int
	maxAge     time.Duration
	reports    map[string]ValidationReport
	order      []string
}

func NewStore(maxReports int, maxAge time.Duration) *Store {
	if maxReports <= 0 {
		maxReports = 16
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	return &Store{maxReports: maxReports, maxAge: maxAge, reports: make(map[string]ValidationReport, maxReports)}
}

func (s *Store) ValidateAndStore(input ValidationInput, now time.Time) ValidationReport {
	if s == nil {
		return Validate(input, now, 24*time.Hour)
	}
	report := Validate(input, now, s.maxAge)
	for _, failure := range report.HardGateFailures {
		if failure.Code != "unrelated_control_action" {
			continue
		}
		observability.Default().Metrics.Inc(observability.MetricUnrelatedControlAction, map[string]string{"service": failure.Service, "set": failure.SetID}, 1)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.reports[report.Generation]; !exists {
		s.order = append(s.order, report.Generation)
	}
	s.reports[report.Generation] = cloneReport(report)
	for len(s.order) > s.maxReports {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.reports, oldest)
	}
	return cloneReport(report)
}

func (s *Store) Get(generation string) (ValidationReport, bool) {
	if s == nil {
		return ValidationReport{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	report, ok := s.reports[strings.TrimSpace(generation)]
	return cloneReport(report), ok
}

func (s *Store) Latest() (ValidationReport, bool) {
	if s == nil {
		return ValidationReport{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.order) == 0 {
		return ValidationReport{}, false
	}
	report, ok := s.reports[s.order[len(s.order)-1]]
	return cloneReport(report), ok
}

func (s *Store) RequirePromotion(generation string, now time.Time) error {
	report, ok := s.Get(generation)
	if !ok {
		return fmt.Errorf("%w for generation %s", ErrValidationMissing, observability.RedactIdentifier(generation))
	}
	if !now.Before(report.ExpiresAt) {
		return fmt.Errorf("%w for generation %s", ErrValidationExpired, observability.RedactIdentifier(generation))
	}
	if !report.PromotionAllowed || !report.Passed || report.UnrelatedControlActionTotal != 0 || report.CrossServiceCacheReuse != 0 || report.CrossServiceRouteReuse != 0 {
		return fmt.Errorf("%w for generation %s (%d hard-gate failures)", ErrValidationFailed, observability.RedactIdentifier(generation), len(report.HardGateFailures))
	}
	return nil
}

func cloneReport(in ValidationReport) ValidationReport {
	in.HardGateFailures = append([]HardGateViolation(nil), in.HardGateFailures...)
	in.Warnings = append([]string(nil), in.Warnings...)
	return in
}

var defaultStore = NewStore(16, 24*time.Hour)

func Default() *Store { return defaultStore }
