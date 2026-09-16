package discovery

import (
	"errors"
	"fmt"
	"sort"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
)

type OperatorDefinition struct {
	Family          detector.StrategyOperatorFamily
	RiskTier        string
	AutomaticSafe   bool
	Compiler        string
	Representations []action.PacketRepresentation
	ParameterDomain map[string][]string
	ExternalParams  []string
	Branches        uint8
	BasePackets     uint16
	BaseCPUUnits    uint32
	BaseLatencyMS   uint32
}

type TriggerDomain struct {
	Phase   string
	Markers []string
}

type GrammarConstraint struct {
	ID          string
	Description string
}

type StrategyGrammar struct {
	Version          string
	Operators        []OperatorDefinition
	TriggerDomains   []TriggerDomain
	Constraints      []GrammarConstraint
	MaxActions       uint8
	MaxBranches      uint8
	MaxAmplification float64
}

func AutomaticStrategyGrammarV1() StrategyGrammar {
	// Action.Plan rejects split offset 0, so automatic split seeds begin at
	// the first non-zero semantic marker rather than ClientHelloStart.
	markerDomain := []string{"host-start", "sni-extension-start", "sld-middle", "host-end"}
	return StrategyGrammar{
		Version: SynthesisGrammarV1,
		Operators: []OperatorDefinition{
			{Family: detector.OperatorTCPSplit, RiskTier: "endpoint-safe", AutomaticSafe: true, Compiler: "plan_strategy", Representations: []action.PacketRepresentation{action.RepresentationNormalTCP, action.RepresentationGSOSafe}, ParameterDomain: map[string][]string{"marker": markerDomain}, BasePackets: 2, BaseCPUUnits: 1},
			{Family: detector.OperatorTLSRecordSplit, RiskTier: "endpoint-safe", AutomaticSafe: true, Compiler: "plan_tls_record_split", Representations: []action.PacketRepresentation{action.RepresentationNormalTCP, action.RepresentationGSOSafe}, ParameterDomain: map[string][]string{"marker": []string{"sni-extension-start", "host-start", "sld-middle", "host-end"}}, BasePackets: 2, BaseCPUUnits: 2},
			{Family: detector.OperatorBoundedDisorder, RiskTier: "endpoint-safe", AutomaticSafe: true, Compiler: "plan_strategy", Representations: []action.PacketRepresentation{action.RepresentationNormalTCP}, ParameterDomain: map[string][]string{"marker": markerDomain, "order": []string{"swap_adjacent_once"}}, BasePackets: 2, BaseCPUUnits: 2, BaseLatencyMS: 1},
			{Family: detector.OperatorSafeDuplicateOriginal, RiskTier: "endpoint-safe", AutomaticSafe: true, Compiler: "action_plan_duplicate", Representations: []action.PacketRepresentation{action.RepresentationNormalTCP}, ParameterDomain: map[string][]string{"count": []string{"1"}}, BasePackets: 1, BaseCPUUnits: 1},
			{Family: detector.OperatorPerFlowJitter, RiskTier: "endpoint-safe", AutomaticSafe: true, Compiler: "action_plan_jitter", Representations: []action.PacketRepresentation{action.RepresentationNormalTCP, action.RepresentationGSOSafe}, ParameterDomain: map[string][]string{"jitter_ms": []string{"0", "1", "2", "4", "8"}}, BaseCPUUnits: 1, BaseLatencyMS: 8},
			{Family: detector.OperatorSafeFakeProfile, RiskTier: "endpoint-safe", AutomaticSafe: true, Compiler: "plan_fake_mix", Representations: []action.PacketRepresentation{action.RepresentationNormalTCP}, ExternalParams: []string{"profile_id"}, ParameterDomain: map[string][]string{"mode": []string{"fakedsplit", "fakeddisorder"}}, BasePackets: 2, BaseCPUUnits: 3},
			{Family: detector.OperatorPrePadding, RiskTier: "endpoint-safe", AutomaticSafe: false, Compiler: "unavailable", Representations: []action.PacketRepresentation{action.RepresentationNormalTCP}, ParameterDomain: map[string][]string{"padding_bytes": []string{"1", "4", "8", "16", "32"}}},
			{Family: detector.OperatorPostPadding, RiskTier: "endpoint-safe", AutomaticSafe: false, Compiler: "unavailable", Representations: []action.PacketRepresentation{action.RepresentationNormalTCP}, ParameterDomain: map[string][]string{"padding_bytes": []string{"1", "4", "8", "16", "32"}}},
		},
		TriggerDomains: []TriggerDomain{
			{Phase: "first-outbound-clienthello", Markers: []string{"clienthello-start", "sni-extension-start", "host-start", "sld-middle", "host-end"}},
			{Phase: "complete-reassembled-clienthello", Markers: []string{"clienthello-start", "sni-extension-start", "host-start", "sld-middle", "host-end", "clienthello-end"}},
			{Phase: "tls-record-boundary", Markers: []string{"clienthello-start", "clienthello-end"}},
		},
		Constraints: []GrammarConstraint{
			{ID: "stream-preserving", Description: "original endpoint-visible logical byte stream is preserved"},
			{ID: "authorization-current", Description: "current ActionAuthorization is required before non-dry-run execution"},
			{ID: "finite-parameters", Description: "all automatic parameters come from finite grammar registries"},
			{ID: "no-direct-apply", Description: "candidate evaluation cannot directly promote or apply configuration"},
		},
		MaxActions: 4, MaxBranches: 1, MaxAmplification: 1.5,
	}
}

func (g StrategyGrammar) Operator(family detector.StrategyOperatorFamily) (OperatorDefinition, bool) {
	for _, op := range g.Operators {
		if op.Family == family { return op, true }
	}
	return OperatorDefinition{}, false
}

func (g StrategyGrammar) Validate() error {
	if g.Version == "" || len(g.Operators) == 0 || len(g.TriggerDomains) == 0 || g.MaxActions == 0 || g.MaxAmplification < 1 {
		return errors.New("invalid strategy grammar")
	}
	seen := map[detector.StrategyOperatorFamily]struct{}{}
	for _, op := range g.Operators {
		if op.Family == "" || op.Compiler == "" { return errors.New("grammar operator is incomplete") }
		if _, ok := seen[op.Family]; ok { return fmt.Errorf("duplicate grammar operator %q", op.Family) }
		seen[op.Family] = struct{}{}
		for name, values := range op.ParameterDomain {
			if name == "" || len(values) == 0 { return fmt.Errorf("operator %q has empty parameter domain", op.Family) }
			copyValues := append([]string(nil), values...)
			sort.Strings(copyValues)
			for i := 1; i < len(copyValues); i++ {
				if copyValues[i] == copyValues[i-1] { return fmt.Errorf("operator %q domain %q contains duplicates", op.Family, name) }
			}
		}
	}
	return nil
}

func (g StrategyGrammar) ValidateOperation(operation CandidateOperation, automatic bool) error {
	definition, ok := g.Operator(operation.Family)
	if !ok { return fmt.Errorf("operator %q is not registered", operation.Family) }
	if automatic && !definition.AutomaticSafe { return fmt.Errorf("operator %q has no automatic ActionPlanner bridge", operation.Family) }
	external := make(map[string]struct{}, len(definition.ExternalParams))
	for _, name := range definition.ExternalParams { external[name] = struct{}{} }
	for name, value := range operation.Params {
		values, known := definition.ParameterDomain[name]
		if !known {
			if _, ok := external[name]; ok && value != "" { continue }
			return fmt.Errorf("operator %q parameter %q is not registered", operation.Family, name)
		}
		matched := false
		for _, allowed := range values { if value == allowed { matched = true; break } }
		if !matched { return fmt.Errorf("operator %q parameter %q value %q is outside finite domain", operation.Family, name, value) }
	}
	for name := range definition.ParameterDomain {
		if _, ok := operation.Params[name]; !ok { return fmt.Errorf("operator %q parameter %q is required", operation.Family, name) }
	}
	for _, name := range definition.ExternalParams {
		if operation.Params[name] == "" { return fmt.Errorf("operator %q external parameter %q is required", operation.Family, name) }
	}
	return nil
}

func (g StrategyGrammar) TriggerAllowed(trigger CandidateTrigger) bool {
	for _, domain := range g.TriggerDomains {
		if trigger.Phase != domain.Phase { continue }
		if trigger.Marker == "" { return true }
		for _, marker := range domain.Markers { if trigger.Marker == marker { return true } }
	}
	return false
}

func representationAllowed(required action.PacketRepresentation, supported []action.PacketRepresentation) bool {
	for _, v := range supported {
		if required == v || required == action.RepresentationAny { return true }
	}
	return false
}
