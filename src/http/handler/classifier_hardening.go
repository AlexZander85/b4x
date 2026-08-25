package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/nfq"
	"github.com/daniellavrushin/b4/observability"
)

const classifierHardeningAPIPath = "/api/v2/classifier/hardening"

type classifierHardeningStatusResponse struct {
	APIVersion        string                     `json:"api_version"`
	ClassifierAPI     string                     `json:"classifier_api_version"`
	GeneratedAt       time.Time                  `json:"generated_at"`
	RuntimeGeneration string                     `json:"runtime_generation,omitempty"`
	GSO               classifierGSOStatus        `json:"gso"`
	PassiveRST        classifierPassiveRSTStatus `json:"passive_rst"`
	Warnings          []string                   `json:"warnings,omitempty"`
}

type classifierGSOStatus struct {
	RequestedMode        string                   `json:"requested_mode"`
	ExecutionPolicy      string                   `json:"execution_policy"`
	MaxGSOBytes          int                      `json:"max_gso_bytes"`
	NormalizeForMutation bool                     `json:"normalize_for_mutation"`
	TCPOnly              bool                     `json:"tcp_only"`
	Capability           nfq.GSOCapabilityStatus  `json:"capability"`
	Readiness            nfq.GSOReadinessSnapshot `json:"readiness"`
	Workers              int                      `json:"workers"`
	Topology             capture.GSOTopologyPlan  `json:"topology"`
	TopologySource       string                   `json:"topology_source"`
	TokenStats           nfq.GSOPassTokenStats    `json:"token_stats"`
	ActiveTokens         int                      `json:"active_tokens"`
}

type classifierPassiveRSTStatus struct {
	RequestedMode        string                         `json:"requested_mode"`
	EffectiveMode        string                         `json:"effective_mode"`
	SetScopes            []string                       `json:"set_scopes,omitempty"`
	DeviceScopes         []string                       `json:"device_scopes,omitempty"`
	VisibilityComplete   int                            `json:"visibility_complete"`
	VisibilityIncomplete int                            `json:"visibility_incomplete"`
	Stats                nfq.PassiveRSTStoreStats       `json:"stats"`
	RecentDecisions      []classifierPassiveRSTDecision `json:"recent_decisions,omitempty"`
	RecentRollbacks      []classifierPassiveRSTRollback `json:"recent_rollbacks,omitempty"`
}

type classifierPassiveRSTSignal struct {
	Signal   string `json:"signal"`
	Strength string `json:"strength"`
}

type classifierPassiveRSTDecision struct {
	FlowID             string                       `json:"flow_id"`
	SetID              string                       `json:"set_id,omitempty"`
	DeviceScope        string                       `json:"device_scope,omitempty"`
	ConfigGeneration   uint64                       `json:"config_generation"`
	ObservedAt         time.Time                    `json:"observed_at"`
	Decision           string                       `json:"decision"`
	Reason             string                       `json:"reason,omitempty"`
	BaselineQuality    string                       `json:"baseline_quality"`
	VisibilityComplete bool                         `json:"visibility_complete"`
	ServerProgress     bool                         `json:"server_progress"`
	BudgetRemaining    int                          `json:"budget_remaining"`
	Signals            []classifierPassiveRSTSignal `json:"signals,omitempty"`
}

type classifierPassiveRSTRollback struct {
	SetID            string    `json:"set_id"`
	DeviceScope      string    `json:"device_scope"`
	ConfigGeneration uint64    `json:"config_generation"`
	Environment      string    `json:"environment"`
	FromMode         string    `json:"from_mode"`
	EffectiveMode    string    `json:"effective_mode"`
	Reason           string    `json:"reason"`
	TriggeredAt      time.Time `json:"triggered_at"`
}

func (api *API) handleClassifierHardeningStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg := api.getCfg()
	if cfg == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "classifier configuration unavailable")
		return
	}
	runtimeCfg := cfg.System.Classifier.Runtime
	status := nfq.HardeningRuntimeStatus{Capability: nfq.GSOCapabilityStatus{Level: nfq.GSOCapabilityUnsupported, Reason: "NFQUEUE pool unavailable"}}
	if globalPool != nil {
		status = globalPool.HardeningRuntimeStatus(runtimeCfg.PassiveRST.RecentDecisionLimit)
	}
	plan, source, warnings := classifierHardeningTopology(cfg)
	out := classifierHardeningStatusResponse{
		APIVersion: config.ClassifierHardeningAPIV1, ClassifierAPI: config.ClassifierAPIV23,
		GeneratedAt: time.Now().UTC(), RuntimeGeneration: cfg.RuntimeGeneration, Warnings: warnings,
		GSO: classifierGSOStatus{
			RequestedMode: runtimeCfg.Capture.NFQueue.GSOMode, ExecutionPolicy: runtimeCfg.Execution.GSOPolicy,
			MaxGSOBytes: runtimeCfg.Capture.NFQueue.MaxGSOBytes, NormalizeForMutation: runtimeCfg.Capture.NFQueue.NormalizeForMutation,
			TCPOnly: runtimeCfg.Capture.NFQueue.TCPOnly, Capability: status.Capability, Readiness: status.Readiness, Workers: len(status.WorkerCapability),
			Topology: plan, TopologySource: source, TokenStats: status.TokenStats, ActiveTokens: status.ActiveTokens,
		},
		PassiveRST: classifierPassiveRSTStatus{
			RequestedMode: runtimeCfg.PassiveRST.Mode, EffectiveMode: runtimeCfg.PassiveRST.Mode,
			SetScopes: redactHardeningIDs(runtimeCfg.PassiveRST.SetScopes), DeviceScopes: redactHardeningIDs(runtimeCfg.PassiveRST.DeviceScopes),
			Stats: status.PassiveRSTStats,
		},
	}
	out.PassiveRST.RecentDecisions, out.PassiveRST.VisibilityComplete, out.PassiveRST.VisibilityIncomplete = redactPassiveRSTDecisions(status.RecentRST)
	out.PassiveRST.RecentRollbacks = redactPassiveRSTRollbacks(status.RecentRollbacks)
	if len(out.PassiveRST.RecentRollbacks) > 0 && (runtimeCfg.PassiveRST.Mode == config.PassiveRSTConservative || runtimeCfg.PassiveRST.Mode == config.PassiveRSTAggressive) {
		out.PassiveRST.EffectiveMode = "scope-dependent"
	}
	sendResponse(w, out)
}

func classifierHardeningTopology(cfg *config.Config) (capture.GSOTopologyPlan, string, []string) {
	if globalGSOTopology != nil {
		return globalGSOTopology.Plan(), "active-transaction", nil
	}
	plan, err := capture.PlanGSOTopology(cfg)
	if err != nil {
		return capture.GSOTopologyPlan{}, "unavailable", []string{"GSO topology plan unavailable: " + err.Error()}
	}
	return plan, "configured", []string{"active transactional topology has not been observed in this process"}
}

func redactHardeningIDs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if redacted := observability.RedactIdentifier(value); redacted != "" {
			out = append(out, redacted)
		}
	}
	return out
}

func redactPassiveRSTDecisions(values []nfq.PassiveRSTEvidence) ([]classifierPassiveRSTDecision, int, int) {
	out := make([]classifierPassiveRSTDecision, 0, len(values))
	complete, incomplete := 0, 0
	for _, value := range values {
		if value.Flow.VisibilityComplete {
			complete++
		} else {
			incomplete++
		}
		decision := classifierPassiveRSTDecision{
			FlowID: observability.RedactIdentifier(fmt.Sprintf("%v", value.Flow.FlowKey)),
			SetID:  observability.RedactIdentifier(value.Flow.SetID), DeviceScope: observability.RedactIdentifier(value.Flow.DeviceScope),
			ConfigGeneration: value.Flow.ConfigGeneration, ObservedAt: value.ObservedAt, Decision: string(value.Decision), Reason: value.Reason,
			BaselineQuality: string(value.Baseline.Quality), VisibilityComplete: value.Flow.VisibilityComplete,
			ServerProgress: value.Flow.ServerPayloadProgress, BudgetRemaining: value.Flow.SuppressionBudget,
		}
		for _, signal := range value.Signals {
			decision.Signals = append(decision.Signals, classifierPassiveRSTSignal{Signal: string(signal.Signal), Strength: string(signal.Strength)})
		}
		out = append(out, decision)
	}
	return out, complete, incomplete
}

func redactPassiveRSTRollbacks(values []nfq.PassiveRSTRollbackState) []classifierPassiveRSTRollback {
	out := make([]classifierPassiveRSTRollback, 0, len(values))
	for _, value := range values {
		out = append(out, classifierPassiveRSTRollback{
			SetID: observability.RedactIdentifier(value.SetID), DeviceScope: observability.RedactIdentifier(value.DeviceScope),
			ConfigGeneration: value.ConfigGeneration, Environment: value.Environment, FromMode: value.FromMode,
			EffectiveMode: value.EffectiveMode, Reason: value.Reason, TriggeredAt: value.TriggeredAt,
		})
	}
	return out
}
