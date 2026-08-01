package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/crossservice"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/runtimecontrol"
	"github.com/daniellavrushin/b4/validation"
)

const runtimeControlAPIPath = "/api/v2/runtime-control"

type runtimeCandidatePatch struct {
	Classifier *config.ClassifierConfig `json:"classifier,omitempty"`
	Sets       []*config.SetConfig      `json:"sets,omitempty"`
}

type runtimeCanaryRequest struct {
	ClientGroup             string  `json:"client_group"`
	SetID                   string  `json:"set_id"`
	Protocol                string  `json:"protocol"`
	NewFlowPercent          uint8   `json:"new_flow_percent"`
	DurationSeconds         int     `json:"duration_seconds"`
	MinSamples              uint64  `json:"min_samples"`
	MaxFailures             uint64  `json:"max_failures"`
	MaxFailureRate          float64 `json:"max_failure_rate"`
	StopOnQueueDrops        bool    `json:"stop_on_queue_drops"`
	StopOnCaptureIncomplete bool    `json:"stop_on_capture_incomplete"`
}

type runtimePrepareRequest struct {
	Candidate runtimeCandidatePatch `json:"candidate"`
	Canary    runtimeCanaryRequest  `json:"canary"`
}

type runtimeReasonRequest struct {
	Reason string `json:"reason"`
}

// InitializeRuntimeControl wires the generic transaction manager to the live
// NFQUEUE/config process after the HTTP server has received the production
// pool. The manager remains disabled unless the classifier feature flag is
// explicitly enabled.
func (api *API) InitializeRuntimeControl(b4Version string) error {
	if api == nil {
		return errors.New("runtime control API is unavailable")
	}
	current := api.getCfg()
	if current == nil {
		return errors.New("active config is unavailable")
	}
	if globalPool == nil {
		if !current.System.Classifier.Flags.TransactionalApplyEnabled {
			return nil
		}
		return errors.New("NFQUEUE pool is unavailable")
	}
	hooks := runtimecontrol.LiveHooks{
		Current: func() *config.Config {
			cfg := api.getCfg()
			if cfg == nil {
				return nil
			}
			return cfg.Clone()
		},
		Apply:         api.ApplyRuntimeControlConfig,
		ApplyTopology: api.ApplyRuntimeControlTopology,
	}
	builder, err := runtimecontrol.NewLiveBuilder(hooks)
	if err != nil {
		return fmt.Errorf("initialize runtime-control builder: %w", err)
	}
	var lastGood runtimecontrol.LastGoodStore = &runtimecontrol.MemoryLastGoodStore{}
	if current.ConfigPath != "" {
		lastGood = &runtimecontrol.FileLastGoodStore{Path: current.ConfigPath + ".last-good.json"}
	}
	manager, err := runtimecontrol.NewManager(builder, runtimecontrol.Options{
		Enabled:      current.System.Classifier.Flags.TransactionalApplyEnabled,
		B4Version:    b4Version,
		LastGood:     lastGood,
		Cooldown:     time.Duration(current.System.Classifier.Runtime.Rollout.CooldownSeconds) * time.Second,
		HistoryLimit: 64,
		BeforePromote: func(meta runtimecontrol.GenerationMeta) error {
			return crossservice.Default().RequirePromotion(meta.ID, time.Now().UTC())
		},
		HardGateCheck: func(meta runtimecontrol.GenerationMeta) error {
			return checkHardGates(current, meta.ID)
		},
	})
	if err != nil {
		return fmt.Errorf("initialize runtime-control manager: %w", err)
	}
	initialRuntime, err := runtimecontrol.NewActiveRuntime(current, hooks)
	if err != nil {
		return fmt.Errorf("initialize active runtime generation: %w", err)
	}
	if err := manager.InstallInitial(current, initialRuntime); err != nil {
		return fmt.Errorf("install initial runtime generation: %w", err)
	}
	api.SetRuntimeControlManager(manager)
	return nil
}

func (api *API) RegisterRuntimeControlAPI() {
	api.mux.HandleFunc(runtimeControlAPIPath+"/status", api.handleRuntimeControlStatus)
	api.mux.HandleFunc(runtimeControlAPIPath+"/prepare", api.handleRuntimeControlPrepare)
	api.mux.HandleFunc(runtimeControlAPIPath+"/canary", api.handleRuntimeControlCanary)
	api.mux.HandleFunc(runtimeControlAPIPath+"/promote", api.handleRuntimeControlPromote)
	api.mux.HandleFunc(runtimeControlAPIPath+"/abort", api.handleRuntimeControlAbort)
	api.mux.HandleFunc(runtimeControlAPIPath+"/rollback", api.handleRuntimeControlRollback)
}

func (api *API) handleRuntimeControlStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	manager := api.getRuntimeControlManager()
	if manager == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "runtime control is not initialized")
		return
	}
	sendResponse(w, manager.Status())
}

func (api *API) handleRuntimeControlPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	manager := api.getRuntimeControlManager()
	if manager == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "runtime control is not initialized")
		return
	}
	if err := api.runtimeControlOperationalGate(); err != nil {
		writeJsonError(w, http.StatusConflict, err.Error())
		return
	}
	var request runtimePrepareRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid runtime prepare request: "+err.Error())
		return
	}
	candidate, err := api.buildRuntimeCandidate(request.Candidate)
	if err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	spec := request.Canary.spec()
	if err := runtimecontrol.ValidateLiveCandidateScope(api.getCfg(), candidate, spec.SetID); err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := manager.Prepare(r.Context(), candidate, runtimecontrol.ApplyRequest{Canary: spec})
	if err != nil {
		writeRuntimeControlError(w, err)
		return
	}
	setJsonHeader(w)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

func (api *API) handleRuntimeControlCanary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	manager := api.getRuntimeControlManager()
	if manager == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "runtime control is not initialized")
		return
	}
	if err := api.runtimeControlOperationalGate(); err != nil {
		writeJsonError(w, http.StatusConflict, err.Error())
		return
	}
	// Canary uses the same evaluation as PromotePending (FB-03 phase E2):
	// the current TestSession/ValidationRun window. Only PASS (or
	// NOT_APPLICABLE with no enabled subsystem, matching fieldtest.
	// CanaryEligible(nil)) admits a canary rollout.
	if pending, ok := manager.Pending(); ok {
		eval := evaluateProductionGates(api.getCfg(), pending.Generation.ID)
		if eval.Verdict != validation.GatePass && eval.Verdict != validation.GateNotApplicable {
			writeJsonError(w, http.StatusConflict, fmt.Sprintf(
				"hard-gate evaluation does not admit canary: verdict %s (%d violations, %d missing, %d counter resets)",
				eval.Verdict, len(eval.Violations), len(eval.Missing), len(eval.CounterReset)))
			return
		}
	}
	outcome, err := manager.RunCanary(r.Context())
	if err != nil {
		writeRuntimeControlError(w, err)
		return
	}
	sendResponse(w, outcome)
}

func (api *API) handleRuntimeControlPromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	manager := api.getRuntimeControlManager()
	if manager == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "runtime control is not initialized")
		return
	}
	result, err := manager.PromotePending(r.Context())
	if err != nil {
		writeRuntimeControlError(w, err)
		return
	}
	sendResponse(w, result)
}

func (api *API) handleRuntimeControlAbort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	manager := api.getRuntimeControlManager()
	if manager == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "runtime control is not initialized")
		return
	}
	request := decodeRuntimeReason(r, "operator abort")
	if err := manager.AbortPending(r.Context(), request.Reason); err != nil {
		writeRuntimeControlError(w, err)
		return
	}
	sendResponse(w, map[string]any{"success": true, "reason": request.Reason})
}

func (api *API) handleRuntimeControlRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	manager := api.getRuntimeControlManager()
	if manager == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "runtime control is not initialized")
		return
	}
	request := decodeRuntimeReason(r, "operator rollback")
	result, err := manager.Rollback(r.Context(), request.Reason)
	if err != nil {
		writeRuntimeControlError(w, err)
		return
	}
	sendResponse(w, result)
}

func decodeRuntimeReason(r *http.Request, fallback string) runtimeReasonRequest {
	request := runtimeReasonRequest{Reason: fallback}
	if r == nil || r.Body == nil {
		return request
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&request)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" {
		request.Reason = fallback
	}
	if len(request.Reason) > 256 {
		request.Reason = request.Reason[:256]
	}
	return request
}

func (r runtimeCanaryRequest) spec() runtimecontrol.CanarySpec {
	return runtimecontrol.CanarySpec{
		ClientGroup: strings.TrimSpace(r.ClientGroup), SetID: strings.TrimSpace(r.SetID),
		Protocol: strings.ToLower(strings.TrimSpace(r.Protocol)), NewFlowPercent: r.NewFlowPercent,
		Duration: time.Duration(r.DurationSeconds) * time.Second, MinSamples: r.MinSamples,
		Stop: runtimecontrol.CanaryStopConditions{
			MaxFailures: r.MaxFailures, MaxFailureRate: r.MaxFailureRate,
			StopOnQueueDrops: r.StopOnQueueDrops, StopOnCaptureIncomplete: r.StopOnCaptureIncomplete,
		},
	}
}

func (api *API) buildRuntimeCandidate(patch runtimeCandidatePatch) (*config.Config, error) {
	current := api.getCfg()
	if current == nil {
		return nil, errors.New("active config is unavailable")
	}
	candidate := current.CloneForRuntimeUpdate()
	changed := false
	if patch.Classifier != nil {
		candidate.System.Classifier = *patch.Classifier
		changed = true
	}
	if patch.Sets != nil {
		candidate.Sets = patch.Sets
		changed = true
	}
	if !changed {
		return nil, errors.New("candidate must include classifier or sets")
	}
	candidate.ConfigPath = current.ConfigPath
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("candidate validation failed: %w", err)
	}
	return candidate, nil
}

// ApplyRuntimeControlConfig is the only live-runtime mutation used by the
// transaction manager. It permits set/classifier changes only. A complete
// config file is prepared and fsynced before packet state changes; the final
// rename happens only after the NFQUEUE snapshot and route resolver are ready.
// Any commit failure restores the previous packet snapshot.
func (api *API) ApplyRuntimeControlConfig(candidate *config.Config) error {
	if api == nil || candidate == nil {
		return errors.New("runtime candidate is nil")
	}
	current := api.getCfg()
	if current == nil {
		return errors.New("active config is unavailable")
	}
	candidate = candidate.Clone()
	candidate.ConfigPath = current.ConfigPath
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("candidate validation failed: %w", err)
	}
	if err := runtimeControlDiffAllowed(current, candidate); err != nil {
		return err
	}
	if fields := preflightConfig(candidate, current); len(fields) > 0 {
		return fmt.Errorf("runtime candidate preflight failed: %s", fields[0].Message)
	}
	if globalPool == nil {
		return errors.New("NFQUEUE pool is unavailable")
	}
	prepared, err := candidate.PrepareSave(candidate.ConfigPath)
	if err != nil {
		return fmt.Errorf("prepare candidate config persistence: %w", err)
	}
	defer prepared.Abort()
	if err := globalPool.UpdateConfig(candidate); err != nil {
		return fmt.Errorf("apply candidate to NFQUEUE pool: %w", err)
	}
	rollback := func(cause error) error {
		var rollbackErrs []error
		if err := globalPool.UpdateConfig(current); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("restore NFQUEUE snapshot: %w", err))
		}
		if routingSyncFunc != nil {
			routingSyncFunc(current)
		}
		if len(rollbackErrs) > 0 {
			return errors.Join(append([]error{cause}, rollbackErrs...)...)
		}
		return cause
	}
	if routingSyncFunc != nil {
		routingSyncFunc(candidate)
	}
	if err := prepared.Commit(); err != nil {
		return rollback(fmt.Errorf("commit candidate config persistence: %w", err))
	}
	api.cfgPtr.Store(candidate)
	return nil
}

func runtimeControlDiffAllowed(active, candidate *config.Config) error {
	if active == nil || candidate == nil {
		return errors.New("transactional runtime apply requires active and candidate configs")
	}
	if active.System.Classifier.Flags.TransactionalApplyEnabled != candidate.System.Classifier.Flags.TransactionalApplyEnabled {
		return errors.New("transactional_apply_enabled cannot change inside a runtime transaction")
	}
	if !reflect.DeepEqual(active.CollectTCPPorts(), candidate.CollectTCPPorts()) ||
		!reflect.DeepEqual(active.CollectUDPPorts(), candidate.CollectUDPPorts()) {
		return errors.New("candidate cannot change the kernel capture port envelope")
	}
	a := active.Clone()
	c := candidate.Clone()
	if err := runtimeControlSetEnvelopeAllowed(a, c); err != nil {
		return err
	}
	c.System.Classifier = a.System.Classifier
	c.Sets = a.Sets
	c.RuntimeGeneration = a.RuntimeGeneration
	c.ConfigPath = a.ConfigPath
	if !reflect.DeepEqual(a, c) {
		return errors.New("transactional runtime apply only permits classifier and set changes")
	}
	return nil
}

func runtimeControlSetEnvelopeAllowed(active, candidate *config.Config) error {
	if len(active.Sets) != len(candidate.Sets) {
		return errors.New("candidate cannot add or remove sets")
	}
	for _, activeSet := range active.Sets {
		if activeSet == nil {
			continue
		}
		candidateSet := candidate.GetSetById(activeSet.Id)
		if candidateSet == nil {
			return fmt.Errorf("candidate cannot remove set %q", activeSet.Id)
		}
		if activeSet.Enabled != candidateSet.Enabled || activeSet.Name != candidateSet.Name ||
			!reflect.DeepEqual(activeSet.Targets, candidateSet.Targets) ||
			!reflect.DeepEqual(activeSet.Routing, candidateSet.Routing) {
			return fmt.Errorf("candidate set %q cannot change identity, targets or routing", activeSet.Id)
		}
	}
	return nil
}

func (api *API) runtimeControlOperationalGate() error {
	if api == nil {
		return errors.New("runtime control API is unavailable")
	}
	if api.discoveryRT != nil && api.discoveryRT.IsActive() {
		return errors.New("Discovery is active; stop it before transactional canary rollout")
	}
	if cfg := api.getCfg(); cfg != nil && cfg.System.Checker.Watchdog.Enabled {
		return errors.New("Watchdog is enabled; disable it before transactional canary rollout")
	}
	return nil
}

func (api *API) EnsureNoPendingRuntimeControl() error {
	manager := api.getRuntimeControlManager()
	if manager == nil {
		return nil
	}
	if _, pending := manager.Pending(); pending {
		return runtimecontrol.ErrPendingBusy
	}
	return nil
}

func (api *API) SetRuntimeControlEnabled(enabled bool) {
	if manager := api.getRuntimeControlManager(); manager != nil {
		manager.SetEnabled(enabled)
	}
}

func (api *API) CloseRuntimeControl(ctx context.Context) error {
	manager := api.getRuntimeControlManager()
	if manager == nil {
		return nil
	}
	return manager.Close(ctx)
}

func writeRuntimeControlError(w http.ResponseWriter, err error) {
	status := http.StatusConflict
	switch {
	case errors.Is(err, runtimecontrol.ErrDisabled):
		status = http.StatusForbidden
	case errors.Is(err, runtimecontrol.ErrInvalidCanary), errors.Is(err, runtimecontrol.ErrInvalidRuntime):
		status = http.StatusBadRequest
	case errors.Is(err, runtimecontrol.ErrNoActive), errors.Is(err, runtimecontrol.ErrNoPending), errors.Is(err, runtimecontrol.ErrNoRollback):
		status = http.StatusNotFound
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status = http.StatusRequestTimeout
	}
	writeJsonError(w, status, err.Error())
}

// hardGateScope projects the canonical hard-gate release scope (FB-03) from
// the active configuration:
//   - WARPBase: classifier v2 pipeline
//   - RSTGSO: classifier/GSO/passive-RST pipeline (same v2 pipeline)
//   - PPE: capture visibility (PPE offload enabled)
//   - CSI: cross-service isolation (wired to promotion via RequirePromotion)
//
// Families without an enabled owning subsystem are NOT_APPLICABLE.
func hardGateScope(cfg *config.Config) validation.ReleaseScope {
	if cfg == nil {
		return validation.ReleaseScope{}
	}
	classifierV2 := cfg.System.Classifier.Flags.ClassifierV2Enabled
	ppeEnabled := classifierV2 &&
		(cfg.System.Classifier.Runtime.Capture.PPE.TCPEnabled || cfg.System.Classifier.Runtime.Capture.PPE.QUICEnabled)
	return validation.ReleaseScope{
		WARPBase: classifierV2,
		CSI:      true,
		RSTGSO:   classifierV2,
		PPE:      ppeEnabled,
	}
}

// checkHardGates evaluates the canonical hard-gate registry (FB-03) as the
// final promotion gate for a candidate generation. It uses the single
// production evaluation path (evaluateProductionGates): the delta of the
// current TestSession/ValidationRun window, never the process-lifetime
// wrapper. Any non-PASS verdict fails the promotion transaction
// (StagePromote).
func checkHardGates(cfg *config.Config, generationID string) error {
	scope := hardGateScope(cfg)
	if !scope.Enabled() {
		return nil // nothing enabled => NOT_APPLICABLE, not a failure
	}
	eval := evaluateProductionGates(cfg, generationID)
	if eval.Verdict == validation.GatePass {
		return nil
	}
	return fmt.Errorf("hard-gate check failed for generation %s: verdict %s (%d violations, %d missing, %d counter resets)",
		observability.RedactIdentifier(generationID), eval.Verdict, len(eval.Violations), len(eval.Missing), len(eval.CounterReset))
}
