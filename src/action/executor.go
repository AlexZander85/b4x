package action

import (
	"context"
	"time"
)

type PacketSender interface {
	Send(packet []byte, processedMark uint32) error
}

type ExecutorConfig struct {
	MTU             int
	MaxWrites       int
	MaxBytes        int
	MaxDelay        time.Duration
	ProcessedMark   uint32
	RequirePlanMark bool
}

func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{MTU: 1500, MaxWrites: 16, MaxBytes: 64 * 1024, MaxDelay: 250 * time.Millisecond, RequirePlanMark: true}
}

type ExecutionResult struct {
	Applied      bool
	DryRun       bool
	FailOpen     bool
	PartialSend  bool
	Sent         int
	Bytes        int
	Reason       string
	BuiltPackets []BuiltPacket
}

type Executor struct {
	config  ExecutorConfig
	sender  PacketSender
	builder PacketBuilder
}

func NewExecutor(cfg ExecutorConfig, sender PacketSender) *Executor {
	defaults := DefaultExecutorConfig()
	if cfg.MTU <= 0 {
		cfg.MTU = defaults.MTU
	}
	if cfg.MaxWrites <= 0 {
		cfg.MaxWrites = defaults.MaxWrites
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaults.MaxBytes
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = defaults.MaxDelay
	}
	return &Executor{config: cfg, sender: sender, builder: PacketBuilder{MTU: cfg.MTU}}
}

func (e *Executor) Execute(original []byte, plan ActionPlan) ExecutionResult {
	return e.ExecuteContext(context.Background(), original, plan)
}

func (e *Executor) ExecuteContext(ctx context.Context, original []byte, plan ActionPlan) ExecutionResult {
	result := ExecutionResult{DryRun: plan.DryRun, BuiltPackets: make([]BuiltPacket, 0, len(plan.Writes))}
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil || !plan.Valid {
		result.FailOpen = true
		result.Reason = "invalid action plan"
		return result
	}
	if e.config.RequirePlanMark && plan.ProcessedMark == 0 {
		result.FailOpen = true
		result.Reason = "action plan has no processed provenance mark"
		return result
	}
	if e.config.ProcessedMark != 0 && plan.ProcessedMark != e.config.ProcessedMark {
		result.FailOpen = true
		result.Reason = "action plan provenance mark does not match executor"
		return result
	}
	if len(plan.Writes) == 0 || len(plan.Writes) > e.config.MaxWrites || plan.TotalBytes > e.config.MaxBytes {
		result.FailOpen = true
		result.Reason = "action plan exceeds executor budget"
		return result
	}
	if plan.DryRun {
		for _, write := range plan.Writes {
			if write.Delay < 0 || write.Delay > e.config.MaxDelay {
				result.FailOpen = true
				result.Reason = "action delay exceeds executor budget"
				return result
			}
		}
		result.Reason = "dry-run plan validated; no packets sent"
		return result
	}
	if e.sender == nil {
		result.FailOpen = true
		result.Reason = "raw sender unavailable"
		return result
	}
	for _, write := range plan.Writes {
		if err := waitActionDelay(ctx, write.Delay, e.config.MaxDelay); err != nil {
			result.FailOpen = true
			result.PartialSend = result.Sent > 0
			result.Reason = err.Error()
			return result
		}
		if result.Bytes+len(write.Payload) > e.config.MaxBytes {
			result.FailOpen = true
			result.PartialSend = result.Sent > 0
			result.Reason = "action bytes exceed executor budget"
			return result
		}
		built, err := e.builder.Build(original, write, plan.ProcessedMark)
		if err != nil || built.ProcessedMark != plan.ProcessedMark {
			result.FailOpen = true
			result.PartialSend = result.Sent > 0
			if err != nil {
				result.Reason = err.Error()
			} else {
				result.Reason = "packet provenance mark verification failed"
			}
			return result
		}
		if err := ValidatePacket(built.Packet); err != nil {
			result.FailOpen = true
			result.PartialSend = result.Sent > 0
			result.Reason = "built packet validation failed: " + err.Error()
			return result
		}
		if err := e.sender.Send(append([]byte(nil), built.Packet...), built.ProcessedMark); err != nil {
			result.FailOpen = true
			result.PartialSend = result.Sent > 0
			result.Reason = "raw send failed: " + err.Error()
			return result
		}
		result.BuiltPackets = append(result.BuiltPackets, built)
		result.Sent++
		result.Bytes += len(write.Payload)
	}
	result.Applied = true
	result.Reason = "all planned packets sent"
	return result
}

func waitActionDelay(ctx context.Context, delay, maxDelay time.Duration) error {
	if delay < 0 || delay > maxDelay {
		return ErrPlanBudget
	}
	if delay == 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
