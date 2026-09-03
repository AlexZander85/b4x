package ppe

import "context"

type SelfTestRunner interface {
	Run(context.Context, SelfTestRequest) CaptureVisibilityResult
}

type visibilitySelfTestRunner struct {
	next SelfTestRunner
	gate *VisibilityGate
}

func WrapSelfTestRunnerWithVisibility(next SelfTestRunner, gate *VisibilityGate) SelfTestRunner {
	if next == nil {
		return nil
	}
	if gate == nil {
		gate = DefaultVisibilityGate()
	}
	return &visibilitySelfTestRunner{next: next, gate: gate}
}

func WrapSelfTestRunnerWithDefaultVisibility(next SelfTestRunner) SelfTestRunner {
	return WrapSelfTestRunnerWithVisibility(next, DefaultVisibilityGate())
}

func (r *visibilitySelfTestRunner) Run(ctx context.Context, request SelfTestRequest) CaptureVisibilityResult {
	result := r.next.Run(ctx, request)
	if r.gate != nil {
		r.gate.PublishSelfTestForGeneration(request.Generation, result)
	}
	return result
}
