package runtimecontrol

import (
	"context"
	"fmt"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
)

type visibilityGuardedBuilder struct {
	next Builder
	gate *ppe.VisibilityGate
}

func WrapBuilderWithDefaultVisibility(next Builder) Builder {
	if next == nil {
		return nil
	}
	return &visibilityGuardedBuilder{next: next, gate: ppe.DefaultVisibilityGate()}
}

func (b *visibilityGuardedBuilder) Build(ctx context.Context, candidate *config.Config, meta GenerationMeta) (Runtime, error) {
	if b == nil || b.next == nil {
		return nil, ErrInvalidRuntime
	}
	if requiresPPEVisibilityProof(candidate) && b.gate != nil {
		b.gate.EnsureRequired(meta.ID, "candidate runtime requires controlled PPE visibility proof")
	}
	runtime, err := b.next.Build(ctx, candidate, meta)
	if err != nil || runtime == nil {
		return runtime, err
	}
	return &visibilityGuardedRuntime{Runtime: runtime, gate: b.gate}, nil
}

type visibilityGuardedRuntime struct {
	Runtime
	gate *ppe.VisibilityGate
}

func (r *visibilityGuardedRuntime) Canary(ctx context.Context, spec CanarySpec) (CanaryOutcome, error) {
	if r == nil || r.Runtime == nil {
		return CanaryOutcome{}, ErrInvalidRuntime
	}
	if r.gate != nil {
		decision := r.gate.Decision(ppe.VisibilityFeatureCanary)
		if !decision.Allowed {
			return CanaryOutcome{}, fmt.Errorf("capture visibility blocks canary: %s", decision.Reason)
		}
	}
	return r.Runtime.Canary(ctx, spec)
}

func (r *visibilityGuardedRuntime) Promote(ctx context.Context) error {
	if r == nil || r.Runtime == nil {
		return ErrInvalidRuntime
	}
	if r.gate != nil {
		decision := r.gate.Decision(ppe.VisibilityFeaturePromotion)
		if !decision.Allowed {
			return fmt.Errorf("capture visibility blocks promotion: %s", decision.Reason)
		}
	}
	return r.Runtime.Promote(ctx)
}

func syncInitialVisibilityRequirement(cfg *config.Config, generation string) {
	if requiresPPEVisibilityProof(cfg) {
		ppe.DefaultVisibilityGate().EnsureRequired(generation, "active runtime requires controlled PPE visibility proof")
	}
}

func requiresPPEVisibilityProof(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	return cfg.System.Classifier.Runtime.Capture.OffloadPolicy == "exclude"
}
