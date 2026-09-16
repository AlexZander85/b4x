package discovery

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
)

var (
	ErrSynthesisActionUnsupported = errors.New("synthesized operator has no existing ActionPlanner bridge")
	ErrSynthesisActionStructure   = errors.New("synthesized candidate has incompatible structural operators")
)

type SynthesisActionContext struct {
	Input               action.PlanInput
	Confidence          uint8
	TCPPhase            string
	CompleteClientHello bool
	FlowHash            uint64
	ClientHelloID       uint64
	ConfigGen           uint64
	Tokens              *action.ActionTokenStore
	Budgets             action.ActionBudgets

	// FakeMixTemplate must come from the existing validated endpoint-safe fake
	// profile registry. The synthesis layer never supplies or mutates raw bytes.
	FakeMixTemplate *action.FakeMixRequest
}

type CompiledSynthesizedAction struct {
	CandidateID string
	ActionPlan  *action.ActionPlan
	FakeMixPlan *action.FakeMixPlan
	DryRun      bool
	Reason      string
}

// CompileSynthesizedCandidate is a pure planner bridge: it emits an existing
// ActionPlan/FakeMixPlan and never executes, requeues, promotes or mutates
// configuration. Callers still own ActionAuthorization, canary and rollout.
func CompileSynthesizedCandidate(candidate SynthesizedCandidatePlan, ctx SynthesisActionContext) (CompiledSynthesizedAction, error) {
	out := CompiledSynthesizedAction{CandidateID: candidate.CandidateID, DryRun: ctx.Input.DryRun}
	if !candidate.ValidIdentity() { return out, errors.New("invalid synthesized candidate identity") }
	if ctx.ConfigGen == 0 || ctx.ConfigGen != candidate.ConfigGeneration || ctx.Input.ConfigGen != candidate.ConfigGeneration {
		return out, errors.New("candidate/action config generation mismatch")
	}
	if len(ctx.Input.Payload) == 0 || ctx.Input.ProcessedMark == 0 { return out, action.ErrInvalidPacket }
	if ctx.Budgets == (action.ActionBudgets{}) { ctx.Budgets = action.DefaultActionBudgets() }

	structural := make([]CandidateOperation, 0, len(candidate.Operations))
	transforms := make([]CandidateOperation, 0, 2)
	var fake *CandidateOperation
	for i := range candidate.Operations {
		op := candidate.Operations[i]
		switch op.Family {
		case detector.OperatorTCPSplit, detector.OperatorTLSRecordSplit, detector.OperatorBoundedDisorder:
			structural = append(structural, op)
		case detector.OperatorSafeFakeProfile:
			if fake != nil || len(structural) != 0 { return out, ErrSynthesisActionStructure }
			copyOp := op
			fake = &copyOp
		case detector.OperatorSafeDuplicateOriginal, detector.OperatorPerFlowJitter:
			transforms = append(transforms, op)
		case detector.OperatorPrePadding, detector.OperatorPostPadding:
			return out, fmt.Errorf("%w: %s", ErrSynthesisActionUnsupported, op.Family)
		default:
			return out, fmt.Errorf("%w: %s", ErrSynthesisActionUnsupported, op.Family)
		}
	}

	if fake != nil {
		if len(transforms) != 0 || len(structural) != 0 { return out, fmt.Errorf("%w: safe fake profile cannot be combined in grammar v1", ErrSynthesisActionStructure) }
		if ctx.FakeMixTemplate == nil { return out, fmt.Errorf("%w: endpoint-safe fake profile template required", ErrSynthesisActionUnsupported) }
		req := *ctx.FakeMixTemplate
		req.Enabled = true
		req.StrategyID = candidate.CandidateID
		req.Real = ctx.Input
		req.Real.DryRun = ctx.Input.DryRun
		req.Confidence = ctx.Confidence
		req.TCPPhase = ctx.TCPPhase
		req.FlowHash = ctx.FlowHash
		req.ClientHelloID = ctx.ClientHelloID
		req.ConfigGen = ctx.ConfigGen
		req.Tokens = ctx.Tokens
		req.Budgets = ctx.Budgets
		switch fake.Params["mode"] {
		case string(action.FakeMixSplit): req.Mode = action.FakeMixSplit
		case string(action.FakeMixDisorder): req.Mode = action.FakeMixDisorder
		default: return out, fmt.Errorf("invalid safe fake mode %q", fake.Params["mode"])
		}
		plan, err := action.PlanFakeMix(req)
		if err != nil { return out, err }
		out.FakeMixPlan = &plan
		out.Reason = "compiled through existing PlanFakeMix"
		return out, nil
	}

	plan, err := compileStructuralActions(candidate, structural, ctx)
	if err != nil { return out, err }
	generatedBytes := 0
	for _, transform := range transforms {
		switch transform.Family {
		case detector.OperatorSafeDuplicateOriginal:
			if len(plan.Writes) == 0 { return out, action.ErrInvalidStreamRange }
			duplicate := plan.Writes[0]
			duplicate.Payload = append([]byte(nil), duplicate.Payload...)
			generatedBytes += len(duplicate.Payload)
			writes := make([]action.PlannedWrite, 0, len(plan.Writes)+1)
			writes = append(writes, plan.Writes[0], duplicate)
			writes = append(writes, plan.Writes[1:]...)
			for i := range writes { writes[i].Order = i }
			plan.Writes = writes
			plan.TotalBytes += len(duplicate.Payload)
		case detector.OperatorPerFlowJitter:
			ms, parseErr := strconv.Atoi(transform.Params["jitter_ms"])
			if parseErr != nil || ms < 0 || ms > 8 { return out, errors.New("invalid bounded jitter") }
			delay := time.Duration(ms) * time.Millisecond
			for i := range plan.Writes { plan.Writes[i].Delay += delay }
		}
	}
	if err := ctx.Budgets.Check(len(ctx.Input.Payload), len(plan.Writes), generatedBytes); err != nil { return out, err }
	plan.StrategyID = candidate.CandidateID
	plan.Reason = "synthesized plan compiled through existing ActionPlanner primitives"
	out.ActionPlan = &plan
	out.Reason = plan.Reason
	return out, nil
}

func compileStructuralActions(candidate SynthesizedCandidatePlan, structural []CandidateOperation, ctx SynthesisActionContext) (action.ActionPlan, error) {
	if len(structural) == 0 {
		plan, err := action.Plan(ctx.Input)
		if err != nil { return action.ActionPlan{}, err }
		return plan, nil
	}
	positions := make([]action.SplitPositionSpec, 0, len(structural))
	technique := action.TechniqueMultiSplit
	order := action.OrderForward
	pre := action.StrategyPreconditions{MinConfidence: 80, RequiresCompleteCH: true, FirstFlightOnly: true, AllowedTCPPhases: []string{ctx.TCPPhase}}
	disorderCount := 0
	for _, operation := range structural {
		marker, err := synthesisMarker(operation.Params["marker"])
		if err != nil { return action.ActionPlan{}, err }
		if marker == action.MarkerSNIExtensionStart || marker == action.MarkerHostStart || marker == action.MarkerHostEnd || marker == action.MarkerSLDMiddle { pre.RequiresClearSNI = true }
		position := action.SplitPositionSpec{Marker: marker}
		positions = append(positions, position)
		switch operation.Family {
		case detector.OperatorBoundedDisorder:
			disorderCount++
			technique, order = action.TechniqueMultiDisorder, action.OrderReverse
		case detector.OperatorTLSRecordSplit:
			// Reuse the specialized parser/marker validator in dry-run mode,
			// then compile all compatible split boundaries into one existing
			// multi-split ActionPlan. No TLS/application bytes are rewritten.
			validationInput := ctx.Input
			validationInput.DryRun = true
			_, err := action.PlanTLSRecordSplit(action.TLSRecordSplitRequest{
				Enabled: true, StrategyID: candidate.CandidateID + "/tls-boundary-check", Input: validationInput,
				Positions: []action.SplitPositionSpec{position}, Preconditions: pre, Budgets: ctx.Budgets,
				Confidence: ctx.Confidence, TCPPhase: ctx.TCPPhase, FlowHash: ctx.FlowHash,
				ClientHelloID: ctx.ClientHelloID, ConfigGen: ctx.ConfigGen,
			})
			if err != nil { return action.ActionPlan{}, err }
		case detector.OperatorTCPSplit:
		default:
			return action.ActionPlan{}, fmt.Errorf("%w: %s", ErrSynthesisActionUnsupported, operation.Family)
		}
	}
	if disorderCount > 1 {
		return action.ActionPlan{}, fmt.Errorf("%w: multiple disorder operators", ErrSynthesisActionStructure)
	}
	definition := action.StrategyDefinition{ID: candidate.CandidateID, Technique: technique, Positions: positions, SegmentOrder: order, Preconditions: pre, Budgets: ctx.Budgets}
	planned, err := action.PlanStrategy(action.StrategyRequest{Input: ctx.Input, Definition: definition, Confidence: ctx.Confidence, TCPPhase: ctx.TCPPhase, CompleteClientHello: ctx.CompleteClientHello, FlowHash: ctx.FlowHash, ClientHelloID: ctx.ClientHelloID, ConfigGen: ctx.ConfigGen, Tokens: ctx.Tokens})
	if err != nil { return action.ActionPlan{}, err }
	return planned.ActionPlan, nil
}

func synthesisMarker(value string) (action.LogicalMarkerKind, error) {
	switch value {
	case string(action.MarkerClientHelloStart): return action.MarkerClientHelloStart, nil
	case string(action.MarkerClientHelloEnd): return action.MarkerClientHelloEnd, nil
	case string(action.MarkerSNIExtensionStart): return action.MarkerSNIExtensionStart, nil
	case string(action.MarkerHostStart): return action.MarkerHostStart, nil
	case string(action.MarkerHostEnd): return action.MarkerHostEnd, nil
	case string(action.MarkerSLDMiddle): return action.MarkerSLDMiddle, nil
	default: return "", fmt.Errorf("unknown logical marker %q", value)
	}
}
