package monitor

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type AdaptiveSynthesisState string

const (
	SynthesisIdle                 AdaptiveSynthesisState = "IDLE"
	SynthesisRegressionCandidate  AdaptiveSynthesisState = "REGRESSION_CANDIDATE"
	SynthesisRegressionConfirmed  AdaptiveSynthesisState = "REGRESSION_CONFIRMED"
	SynthesisBehavioralProfiling  AdaptiveSynthesisState = "BEHAVIORAL_PROFILING"
	SynthesisPlanning             AdaptiveSynthesisState = "SYNTHESIS_PLANNING"
	SynthesisDiscoveryTest        AdaptiveSynthesisState = "DISCOVERY_TEST"
	SynthesisAndroidCanary        AdaptiveSynthesisState = "ANDROID_CANARY"
	SynthesisRollout              AdaptiveSynthesisState = "ROLLOUT"
	SynthesisStabilityObserve     AdaptiveSynthesisState = "STABILITY_OBSERVE"
	SynthesisCooldown             AdaptiveSynthesisState = "COOLDOWN"
	SynthesisCancelled            AdaptiveSynthesisState = "CANCELLED"
	SynthesisExhausted            AdaptiveSynthesisState = "EXHAUSTED"
	SynthesisStaleContext         AdaptiveSynthesisState = "STALE_CONTEXT"
)

const (
	maxSynthesisReasons    = 16
	maxSynthesisReasonSize = 256
)

// AdaptiveSynthesisStatus extends the existing Monitoring read model with
// bounded lifecycle metadata only. Candidate generation, packet operations,
// Discovery evaluation and runtime promotion remain owned by their existing
// subsystems.
type AdaptiveSynthesisStatus struct {
	Enabled              bool
	State                AdaptiveSynthesisState
	Scope                MonitorScopeKey
	RunID                string
	TriggerAssessmentID  string
	BehavioralEvidenceID string
	BlockingProfileID    string

	CandidatesGenerated uint16
	CandidatesRejected  uint16
	CandidatesTested    uint16
	CurrentGeneration   uint8
	BestCandidateID     string
	WinnerCandidateID   string
	RolloutGeneration   string

	StartedAt       time.Time
	UpdatedAt       time.Time
	Deadline        time.Time
	NextEligibleRun time.Time
	Reasons         []string
}

// AdaptiveSynthesisUpdate is an ID/counter-only lifecycle handoff. It cannot
// carry packet programs, candidate operations, arbitrary payloads or apply
// authority across the Monitoring boundary.
type AdaptiveSynthesisUpdate struct {
	RunID                string
	State                AdaptiveSynthesisState
	BlockingProfileID    string
	BehavioralEvidenceID string
	CandidatesGenerated  uint16
	CandidatesRejected   uint16
	CandidatesTested     uint16
	CurrentGeneration    uint8
	BestCandidateID      string
	WinnerCandidateID    string
	RolloutGeneration    string
	NextEligibleRun      time.Time
	Reason               string
}

// OpenAdaptiveSynthesis records a persistent-regression owner on an existing
// Monitoring scope. Ordinary ABD revalidation remains the next existing
// monitor/detector handoff; this method does not run Discovery or synthesis.
func (c *FlowCorrelator) OpenAdaptiveSynthesis(assessment MonitorAssessment, runID string, enabled, persistentRegressionQualified bool, deadline, now time.Time) error {
	if c == nil {
		return errors.New("monitor correlator is nil")
	}
	if !enabled {
		return errors.New("adaptive synthesis is not enabled")
	}
	if !persistentRegressionQualified {
		return errors.New("persistent regression is not qualified")
	}
	if !assessment.Valid(now) {
		return errors.New("fresh monitoring assessment required")
	}
	if aggregate := assessment.Aggregate(); aggregate != AxisDegraded && aggregate != AxisFailing {
		return errors.New("degraded or failing monitoring assessment required")
	}
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return errors.New("synthesis run id required")
	}
	if deadline.IsZero() || !deadline.After(now) {
		return errors.New("bounded synthesis deadline required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := c.flows[correlationKey(assessment.Scope)]
	if snapshot == nil {
		return errors.New("existing monitoring correlation scope required")
	}
	current := normalizeSynthesisStatus(snapshot.AdaptiveSynthesis, assessment.Scope)
	if synthesisStateActive(current.State) && current.RunID != runID {
		return errors.New("another synthesis run already owns monitoring scope")
	}
	if current.State == SynthesisCooldown && !current.NextEligibleRun.IsZero() && now.Before(current.NextEligibleRun) {
		return errors.New("synthesis scope is in cooldown")
	}
	if current.State != SynthesisIdle && current.State != SynthesisCancelled && current.State != SynthesisExhausted && current.State != SynthesisStaleContext && current.State != SynthesisCooldown && current.RunID != runID {
		return fmt.Errorf("cannot open synthesis from state %s", current.State)
	}

	snapshot.AdaptiveSynthesis = AdaptiveSynthesisStatus{
		Enabled:             true,
		State:               SynthesisRegressionConfirmed,
		Scope:               assessment.Scope,
		RunID:               runID,
		TriggerAssessmentID: assessment.AssessmentID,
		StartedAt:           now,
		UpdatedAt:           now,
		Deadline:            deadline,
		Reasons:             appendSynthesisReason(nil, "persistent-regression-confirmed; ordinary-abd-revalidation-required"),
	}
	return nil
}

func (c *FlowCorrelator) UpdateAdaptiveSynthesis(scope MonitorScopeKey, update AdaptiveSynthesisUpdate, now time.Time) error {
	if c == nil || !scope.Valid() {
		return errors.New("valid monitoring scope required")
	}
	if now.IsZero() || update.State == "" {
		return errors.New("synthesis state and update time required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := c.flows[correlationKey(scope)]
	if snapshot == nil {
		return errors.New("monitoring correlation scope not found")
	}
	current := normalizeSynthesisStatus(snapshot.AdaptiveSynthesis, scope)
	update.RunID = strings.TrimSpace(update.RunID)
	if current.State == SynthesisIdle {
		return errors.New("synthesis lifecycle has not been opened")
	}
	if update.RunID == "" || update.RunID != current.RunID {
		return errors.New("synthesis run ownership mismatch")
	}
	if !current.Deadline.IsZero() && now.After(current.Deadline) && !synthesisTerminalState(update.State) && update.State != SynthesisCooldown {
		return errors.New("synthesis lifecycle deadline exceeded")
	}
	if update.State != current.State && !allowedSynthesisTransition(current.State, update.State) {
		return fmt.Errorf("invalid synthesis transition %s -> %s", current.State, update.State)
	}
	if update.CandidatesGenerated < current.CandidatesGenerated || update.CandidatesRejected < current.CandidatesRejected || update.CandidatesTested < current.CandidatesTested || update.CurrentGeneration < current.CurrentGeneration {
		return errors.New("synthesis counters/generation must be monotonic")
	}
	if err := bindSynthesisID(&current.BlockingProfileID, update.BlockingProfileID, "blocking profile"); err != nil {
		return err
	}
	if err := bindSynthesisID(&current.BehavioralEvidenceID, update.BehavioralEvidenceID, "behavioral evidence"); err != nil {
		return err
	}

	current.State = update.State
	current.CandidatesGenerated = update.CandidatesGenerated
	current.CandidatesRejected = update.CandidatesRejected
	current.CandidatesTested = update.CandidatesTested
	current.CurrentGeneration = update.CurrentGeneration
	if update.BestCandidateID != "" {
		current.BestCandidateID = update.BestCandidateID
	}
	if update.WinnerCandidateID != "" {
		current.WinnerCandidateID = update.WinnerCandidateID
	}
	if update.RolloutGeneration != "" {
		current.RolloutGeneration = update.RolloutGeneration
	}
	if !update.NextEligibleRun.IsZero() {
		current.NextEligibleRun = update.NextEligibleRun
	}
	current.Reasons = appendSynthesisReason(current.Reasons, update.Reason)
	current.UpdatedAt = now
	snapshot.AdaptiveSynthesis = current
	return nil
}

// CancelAdaptiveSynthesis is idempotent for the owning run. It changes only
// Monitoring lifecycle state; candidate drain/cleanup and production rollback
// stay with the existing Discovery/runtime owners.
func (c *FlowCorrelator) CancelAdaptiveSynthesis(scope MonitorScopeKey, runID, reason string, nextEligibleRun, now time.Time) error {
	if c == nil || !scope.Valid() {
		return errors.New("valid monitoring scope required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := c.flows[correlationKey(scope)]
	if snapshot == nil {
		return nil
	}
	current := normalizeSynthesisStatus(snapshot.AdaptiveSynthesis, scope)
	if current.State == SynthesisIdle {
		return nil
	}
	if strings.TrimSpace(runID) != "" && current.RunID != strings.TrimSpace(runID) {
		return errors.New("synthesis run ownership mismatch")
	}
	if current.State != SynthesisCancelled {
		if !synthesisStateActive(current.State) && current.State != SynthesisStaleContext && current.State != SynthesisExhausted && current.State != SynthesisCooldown {
			return fmt.Errorf("cannot cancel synthesis from state %s", current.State)
		}
		current.State = SynthesisCancelled
	}
	current.NextEligibleRun = nextEligibleRun
	current.Reasons = appendSynthesisReason(current.Reasons, reason)
	current.UpdatedAt = now
	snapshot.AdaptiveSynthesis = current
	return nil
}

func (c *FlowCorrelator) MarkAdaptiveSynthesisStale(scope MonitorScopeKey, runID, reason string, now time.Time) error {
	return c.UpdateAdaptiveSynthesis(scope, AdaptiveSynthesisUpdate{RunID: runID, State: SynthesisStaleContext, Reason: reason}, now)
}

// ObserveAdaptiveSynthesisStability closes Monitoring's post-promotion watch.
// A failed stability window is marked cancelled so the existing transactional
// runtime can roll back and Discovery can quarantine the promoted winner.
func (c *FlowCorrelator) ObserveAdaptiveSynthesisStability(scope MonitorScopeKey, runID, winnerID string, stable bool, nextEligibleRun time.Time, reason string, now time.Time) error {
	state := SynthesisCancelled
	if stable {
		state = SynthesisCooldown
	}
	if reason == "" {
		if stable {
			reason = "post-promotion-stability-observed"
		} else {
			reason = "post-promotion-regression; rollback-and-quarantine-required"
		}
	}
	return c.UpdateAdaptiveSynthesis(scope, AdaptiveSynthesisUpdate{
		RunID:             runID,
		State:             state,
		WinnerCandidateID: winnerID,
		NextEligibleRun:   nextEligibleRun,
		Reason:            reason,
	}, now)
}

func (c *FlowCorrelator) ResetAdaptiveSynthesis(scope MonitorScopeKey, now time.Time) error {
	if c == nil || !scope.Valid() {
		return errors.New("valid monitoring scope required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := c.flows[correlationKey(scope)]
	if snapshot == nil {
		return nil
	}
	current := normalizeSynthesisStatus(snapshot.AdaptiveSynthesis, scope)
	if current.State == SynthesisCooldown && !current.NextEligibleRun.IsZero() && now.Before(current.NextEligibleRun) {
		return errors.New("synthesis cooldown has not elapsed")
	}
	if current.State != SynthesisIdle && current.State != SynthesisCooldown && !synthesisTerminalState(current.State) {
		return fmt.Errorf("cannot reset active synthesis state %s", current.State)
	}
	snapshot.AdaptiveSynthesis = AdaptiveSynthesisStatus{Enabled: current.Enabled, State: SynthesisIdle, Scope: scope, UpdatedAt: now}
	return nil
}

func (c *FlowCorrelator) AdaptiveSynthesisStatus(scope MonitorScopeKey) (AdaptiveSynthesisStatus, bool) {
	snapshot, ok := c.Snapshot(scope)
	if !ok {
		return AdaptiveSynthesisStatus{}, false
	}
	status := normalizeSynthesisStatus(snapshot.AdaptiveSynthesis, scope)
	status.Reasons = append([]string(nil), status.Reasons...)
	return status, true
}

func normalizeSynthesisStatus(status AdaptiveSynthesisStatus, scope MonitorScopeKey) AdaptiveSynthesisStatus {
	if status.State == "" {
		status.State = SynthesisIdle
	}
	if !status.Scope.Valid() {
		status.Scope = scope
	}
	return status
}

func synthesisStateActive(state AdaptiveSynthesisState) bool {
	switch state {
	case SynthesisRegressionCandidate, SynthesisRegressionConfirmed, SynthesisBehavioralProfiling, SynthesisPlanning, SynthesisDiscoveryTest, SynthesisAndroidCanary, SynthesisRollout, SynthesisStabilityObserve:
		return true
	default:
		return false
	}
}

func synthesisTerminalState(state AdaptiveSynthesisState) bool {
	switch state {
	case SynthesisCancelled, SynthesisExhausted, SynthesisStaleContext:
		return true
	default:
		return false
	}
}

func allowedSynthesisTransition(from, to AdaptiveSynthesisState) bool {
	if from == to {
		return true
	}
	allowed := map[AdaptiveSynthesisState][]AdaptiveSynthesisState{
		SynthesisRegressionCandidate: {SynthesisRegressionConfirmed, SynthesisCancelled, SynthesisStaleContext},
		SynthesisRegressionConfirmed: {SynthesisBehavioralProfiling, SynthesisPlanning, SynthesisCancelled, SynthesisStaleContext, SynthesisExhausted},
		SynthesisBehavioralProfiling: {SynthesisPlanning, SynthesisCancelled, SynthesisStaleContext, SynthesisExhausted},
		SynthesisPlanning:            {SynthesisDiscoveryTest, SynthesisCancelled, SynthesisStaleContext, SynthesisExhausted},
		SynthesisDiscoveryTest:       {SynthesisAndroidCanary, SynthesisCancelled, SynthesisStaleContext, SynthesisExhausted},
		SynthesisAndroidCanary:       {SynthesisRollout, SynthesisCancelled, SynthesisStaleContext, SynthesisExhausted},
		SynthesisRollout:             {SynthesisStabilityObserve, SynthesisCancelled, SynthesisStaleContext},
		SynthesisStabilityObserve:    {SynthesisCooldown, SynthesisCancelled, SynthesisStaleContext, SynthesisExhausted},
		SynthesisCooldown:            {SynthesisIdle},
		SynthesisCancelled:           {SynthesisCooldown, SynthesisIdle},
		SynthesisExhausted:           {SynthesisCooldown, SynthesisIdle},
		SynthesisStaleContext:        {SynthesisCooldown, SynthesisIdle},
	}
	for _, candidate := range allowed[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

func bindSynthesisID(current *string, next, name string) error {
	next = strings.TrimSpace(next)
	if next == "" {
		return nil
	}
	if *current != "" && *current != next {
		return fmt.Errorf("%s identity changed inside synthesis run", name)
	}
	*current = next
	return nil
}

func appendSynthesisReason(reasons []string, reason string) []string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return reasons
	}
	if len(reason) > maxSynthesisReasonSize {
		reason = reason[:maxSynthesisReasonSize]
	}
	if len(reasons) > 0 && reasons[len(reasons)-1] == reason {
		return reasons
	}
	reasons = append(reasons, reason)
	if len(reasons) > maxSynthesisReasons {
		reasons = append([]string(nil), reasons[len(reasons)-maxSynthesisReasons:]...)
	}
	return reasons
}
