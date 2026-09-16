package discovery

import (
	"errors"
	"fmt"

	"github.com/daniellavrushin/b4/observability"
)

// CheckSynthesizedEmission is the final finite-grammar boundary before a
// synthesized candidate enters the existing Discovery evaluator. Internal
// mutation attempts may be rejected freely, but anything emitted across this
// boundary must be registered, finite and automatic-safe.
func CheckSynthesizedEmission(candidate SynthesizedCandidatePlan) error {
	return checkSynthesizedEmission(candidate, AutomaticStrategyGrammarV1())
}

// checkSynthesizedEmission keeps the production boundary on the canonical
// grammar while allowing fault-injection tests to exercise the unsafe-operator
// branch without keeping a deliberately unsafe operator in the production
// grammar registry.
func checkSynthesizedEmission(candidate SynthesizedCandidatePlan, grammar StrategyGrammar) error {
	if candidate.GrammarVersion != grammar.Version || !grammar.TriggerAllowed(candidate.Trigger) {
		observability.RecordSynthesisViolation(observability.MetricSynthesisGrammarEscape)
		return errors.New("synthesized candidate escaped the active grammar version or trigger domain")
	}
	for _, operation := range candidate.Operations {
		definition, ok := grammar.Operator(operation.Family)
		if !ok {
			observability.RecordSynthesisViolation(observability.MetricSynthesisGrammarEscape)
			return fmt.Errorf("synthesized operator %q is not registered", operation.Family)
		}
		if !definition.AutomaticSafe || definition.Compiler == "unavailable" {
			observability.RecordSynthesisViolation(observability.MetricSynthesisUnsafeOperatorEmitted)
			return fmt.Errorf("synthesized operator %q is not automatic-safe", operation.Family)
		}
		if err := grammar.ValidateOperation(operation, false); err != nil {
			observability.RecordSynthesisViolation(observability.MetricSynthesisGrammarEscape)
			return err
		}
	}
	return nil
}

// RejectSynthesizedDirectApply protects the architectural boundary even if a
// future shared Discovery implementation accidentally starts applying its
// result. AFS evaluation must remain diagnostic-only until runtimecontrol.
func RejectSynthesizedDirectApply(result AdaptiveRunResult) error {
	if !result.Applied {
		return nil
	}
	observability.RecordSynthesisViolation(observability.MetricSynthesisCandidateDirectApply)
	return errors.New("synthesized Discovery result attempted direct apply")
}
