// Package runtimecontrol owns the control-plane transaction for a B4 runtime
// generation. It deliberately does not inspect packets or hold flow state.
package runtimecontrol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
)

const (
	LastGoodSchemaVersion = 1
	DefaultHistoryLimit   = 64
	DefaultCooldown       = 30 * time.Second
	MaxCanaryDuration     = time.Hour
	MaxCanarySamples      = 1000000
)

var (
	ErrDisabled       = errors.New("transactional runtime apply is disabled")
	ErrNoActive       = errors.New("no active runtime generation")
	ErrNoRollback     = errors.New("no previous last-good generation is available for rollback")
	ErrCooldown       = errors.New("candidate is in cooldown")
	ErrInvalidCanary  = errors.New("invalid canary specification")
	ErrInvalidRuntime = errors.New("runtime implementation is nil")
	ErrPendingExists  = errors.New("a candidate generation is already pending")
	ErrNoPending      = errors.New("no candidate generation is pending")
	ErrCanaryRequired = errors.New("candidate canary has not completed successfully")
	ErrPendingBusy    = errors.New("candidate generation operation is in progress")
)

type Stage string

const (
	StageValidate  Stage = "validate"
	StageBuild     Stage = "build"
	StageReadiness Stage = "readiness"
	StageCanary    Stage = "canary"
	StagePrepare   Stage = "last-good-prepare"
	StagePromote   Stage = "promote"
	StageCommit    Stage = "last-good-commit"
	StageDrain     Stage = "drain"
	StageRollback  Stage = "rollback"
	StageAbort     Stage = "abort"
)

// TransactionError preserves the failure stage for API/trace consumers.
type TransactionError struct {
	Stage Stage
	Err   error
}

func (e *TransactionError) Error() string {
	if e == nil {
		return "runtime transaction failed"
	}
	return fmt.Sprintf("runtime transaction %s: %v", e.Stage, e.Err)
}

func (e *TransactionError) Unwrap() error { return e.Err }

type ValidationSummary struct {
	Valid        bool      `json:"valid"`
	Errors       []string  `json:"errors,omitempty"`
	CheckedAt    time.Time `json:"checked_at"`
	ConfigSchema int       `json:"config_schema"`
}

type GenerationMeta struct {
	ID            string            `json:"id"`
	ConfigHash    string            `json:"config_hash"`
	SchemaVersion int               `json:"schema_version"`
	StrategyIDs   []string          `json:"strategy_ids,omitempty"`
	SetIDs        []string          `json:"set_ids,omitempty"`
	Validation    ValidationSummary `json:"validation"`
	CreatedAt     time.Time         `json:"created_at"`
}

func (m GenerationMeta) clone() GenerationMeta {
	m.StrategyIDs = append([]string(nil), m.StrategyIDs...)
	m.SetIDs = append([]string(nil), m.SetIDs...)
	m.Validation.Errors = append([]string(nil), m.Validation.Errors...)
	return m
}

type RuntimeReadiness struct {
	Ready      bool      `json:"ready"`
	CheckedAt  time.Time `json:"checked_at"`
	Reason     string    `json:"reason,omitempty"`
	QueueDrops uint64    `json:"queue_drops,omitempty"`
	UserDrops  uint64    `json:"user_drops,omitempty"`
}

// Runtime is an allocated but not-yet-promoted immutable generation. The
// implementation owns queue workers, held-flow cleanup and action-token
// invalidation. Every method must be bounded and idempotent where noted.
type Runtime interface {
	Readiness(context.Context) (RuntimeReadiness, error)
	Canary(context.Context, CanarySpec) (CanaryOutcome, error)
	Promote(context.Context) error
	// Drain is a declared intentional no-op: the ARCH §75 "atomic generation
	// switch → drain/retire previous generation" contract is executed by
	// Promote (stopCandidate) and by per-store InvalidateGeneration
	// (routing.BindingStore, nfq.GSOPassTokenStore/ActionTokenStore,
	// classifier.HostHintStore, silentpath.ProgressStore, ...); there is no
	// separate per-generation resource to drain in the production Runtime.
	// Implementations with real drainable resources MUST implement it; the
	// live runtime keeps it as a documented no-op so call sites cannot
	// silently inherit a fake protective drain.
	Drain(context.Context) error
	Resume(context.Context) error
	Rollback(context.Context, string) error
	Close(context.Context) error
}

type Builder interface {
	Build(context.Context, *config.Config, GenerationMeta) (Runtime, error)
}

type BuilderFunc func(context.Context, *config.Config, GenerationMeta) (Runtime, error)

func (f BuilderFunc) Build(ctx context.Context, cfg *config.Config, meta GenerationMeta) (Runtime, error) {
	if f == nil {
		return nil, ErrInvalidRuntime
	}
	return f(ctx, cfg, meta)
}

type CanaryStopConditions struct {
	MaxFailures             uint64  `json:"max_failures,omitempty"`
	MaxFailureRate          float64 `json:"max_failure_rate,omitempty"`
	StopOnQueueDrops        bool    `json:"stop_on_queue_drops,omitempty"`
	StopOnCaptureIncomplete bool    `json:"stop_on_capture_incomplete,omitempty"`
}

type CanarySpec struct {
	ClientGroup    string               `json:"client_group"`
	SetID          string               `json:"set_id"`
	Protocol       string               `json:"protocol"`
	NewFlowPercent uint8                `json:"new_flow_percent"`
	Duration       time.Duration        `json:"duration"`
	MinSamples     uint64               `json:"min_samples"`
	Stop           CanaryStopConditions `json:"stop_conditions"`
}

func (s CanarySpec) Validate() error {
	clientGroup := strings.TrimSpace(s.ClientGroup)
	if clientGroup == "" || strings.TrimSpace(s.SetID) == "" {
		return fmt.Errorf("%w: client_group and set_id are required", ErrInvalidCanary)
	}
	switch {
	case strings.HasPrefix(clientGroup, "ip:"):
		address, err := netip.ParseAddr(strings.TrimSpace(strings.TrimPrefix(clientGroup, "ip:")))
		if err != nil || !address.IsValid() || address.IsUnspecified() {
			return fmt.Errorf("%w: client_group contains an invalid IP address", ErrInvalidCanary)
		}
	case strings.HasPrefix(clientGroup, "mac:"):
		hardware, err := net.ParseMAC(strings.TrimSpace(strings.TrimPrefix(clientGroup, "mac:")))
		if err != nil || len(hardware) != 6 {
			return fmt.Errorf("%w: client_group contains an invalid MAC address", ErrInvalidCanary)
		}
	default:
		return fmt.Errorf("%w: client_group must be ip:<address> or mac:<address>", ErrInvalidCanary)
	}
	if s.NewFlowPercent == 0 || s.NewFlowPercent > 100 {
		return fmt.Errorf("%w: new_flow_percent must be 1..100", ErrInvalidCanary)
	}
	if s.Duration <= 0 || s.Duration > MaxCanaryDuration {
		return fmt.Errorf("%w: duration must be greater than zero and at most %s", ErrInvalidCanary, MaxCanaryDuration)
	}
	if s.MinSamples == 0 || s.MinSamples > MaxCanarySamples {
		return fmt.Errorf("%w: min_samples must be 1..%d", ErrInvalidCanary, MaxCanarySamples)
	}
	if s.Stop.MaxFailures == 0 && s.Stop.MaxFailureRate <= 0 && !s.Stop.StopOnQueueDrops && !s.Stop.StopOnCaptureIncomplete {
		return fmt.Errorf("%w: at least one explicit stop condition is required", ErrInvalidCanary)
	}
	if s.Stop.MaxFailureRate < 0 || s.Stop.MaxFailureRate > 1 {
		return fmt.Errorf("%w: max_failure_rate must be between 0 and 1", ErrInvalidCanary)
	}
	return nil
}

type CanaryOutcome struct {
	Passed            bool      `json:"passed"`
	FlowsStarted      uint64    `json:"flows_started,omitempty"`
	Samples           uint64    `json:"samples"`
	IncomingProgress  uint64    `json:"incoming_progress,omitempty"`
	IncompleteFlows   uint64    `json:"incomplete_flows,omitempty"`
	Failures          uint64    `json:"failures"`
	FailureRate       float64   `json:"failure_rate"`
	QueueDrops        uint64    `json:"queue_drops,omitempty"`
	CaptureIncomplete bool      `json:"capture_incomplete,omitempty"`
	StopReason        string    `json:"stop_reason,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	CompletedAt       time.Time `json:"completed_at"`
}

type ApplyRequest struct {
	Canary CanarySpec
}

type ApplyResult struct {
	Generation GenerationMeta   `json:"generation"`
	Readiness  RuntimeReadiness `json:"readiness"`
	Canary     CanaryOutcome    `json:"canary"`
	DrainError string           `json:"drain_error,omitempty"`
}

type RollbackResult struct {
	Generation GenerationMeta `json:"generation"`
	Reason     string         `json:"reason"`
}

type PrepareResult struct {
	Generation GenerationMeta   `json:"generation"`
	Readiness  RuntimeReadiness `json:"readiness"`
}

type PendingGeneration struct {
	Generation     GenerationMeta   `json:"generation"`
	Readiness      RuntimeReadiness `json:"readiness"`
	CanarySpec     CanarySpec       `json:"canary_spec"`
	Canary         CanaryOutcome    `json:"canary,omitempty"`
	CanaryComplete bool             `json:"canary_complete"`
	CanaryRunning  bool             `json:"canary_running"`
	PreparedAt     time.Time        `json:"prepared_at"`
}

type ManagerStatus struct {
	Enabled  bool               `json:"enabled"`
	Active   *GenerationMeta    `json:"active,omitempty"`
	Pending  *PendingGeneration `json:"pending,omitempty"`
	LastGood *LastGoodRecord    `json:"last_good,omitempty"`
	History  []HistoryEntry     `json:"history,omitempty"`
}

type LastGoodRecord struct {
	SchemaVersion  int               `json:"schema_version"`
	ConfigHash     string            `json:"config_hash"`
	GenerationHash string            `json:"generation_hash"`
	StrategyIDs    []string          `json:"strategy_ids,omitempty"`
	SetIDs         []string          `json:"set_ids,omitempty"`
	Validation     ValidationSummary `json:"validation"`
	B4Version      string            `json:"b4_version"`
	Timestamp      time.Time         `json:"timestamp"`
	Canary         CanaryOutcome     `json:"canary_outcome"`
}

func recordFrom(meta GenerationMeta, outcome CanaryOutcome, version string, now time.Time) LastGoodRecord {
	return LastGoodRecord{
		SchemaVersion: LastGoodSchemaVersion, ConfigHash: meta.ConfigHash, GenerationHash: meta.ID,
		StrategyIDs: append([]string(nil), meta.StrategyIDs...), SetIDs: append([]string(nil), meta.SetIDs...),
		Validation: meta.Validation, B4Version: limitString(version, 128), Timestamp: now, Canary: outcome,
	}
}

func (r LastGoodRecord) clone() LastGoodRecord {
	r.StrategyIDs = append([]string(nil), r.StrategyIDs...)
	r.SetIDs = append([]string(nil), r.SetIDs...)
	r.Validation.Errors = append([]string(nil), r.Validation.Errors...)
	return r
}

// LastGoodStore persists metadata only. It must never persist live flows,
// hints, raw packets or mutable runtime pointers.
