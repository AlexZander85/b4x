package ppe

import (
	"context"
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/config"
)

type FunctionalVerdict string

const (
	FunctionalNotRun       FunctionalVerdict = "not_run"
	FunctionalUnsupported  FunctionalVerdict = "unsupported"
	FunctionalInconclusive FunctionalVerdict = "inconclusive"
	FunctionalFail         FunctionalVerdict = "fail"
	FunctionalPass         FunctionalVerdict = "pass"
)

type DiagnosticState string

const (
	DiagnosticUnsupported      DiagnosticState = "unsupported"
	DiagnosticCapabilityOnly   DiagnosticState = "capability_only"
	DiagnosticRulesUnobserved  DiagnosticState = "rules_unobserved"
	DiagnosticPassiveOutgoing  DiagnosticState = "passive_outgoing_only"
	DiagnosticPassiveEvidence  DiagnosticState = "passive_bidirectional_evidence"
	DiagnosticSuspectedBlind   DiagnosticState = "suspected_offload_blindness"
	DiagnosticConfigurationErr DiagnosticState = "configuration_error"
)

type DiagnosticsReport struct {
	CheckedAt         time.Time         `json:"checked_at"`
	State             DiagnosticState   `json:"state"`
	Capability        CapabilityReport  `json:"capability"`
	DesiredGeneration string            `json:"desired_generation,omitempty"`
	RuleCounters      CounterReport     `json:"rule_counters"`
	Passive           PassiveSnapshot   `json:"passive"`
	FunctionalVerdict FunctionalVerdict `json:"functional_verdict"`
	ProductionReady   bool              `json:"production_ready"`
	Reasons           []string          `json:"reasons,omitempty"`
}

type CapabilityProvider interface {
	Detect(context.Context) CapabilityReport
}

type ConfigProvider func() *config.Config

type DiagnosticsService struct {
	configProvider   ConfigProvider
	capabilities     CapabilityProvider
	counters         *RuleCounterCollector
	passive          *PassiveTracker
	managedSourceSet string
	now              func() time.Time
}

func NewDiagnosticsService(provider ConfigProvider, capabilities CapabilityProvider, counters *RuleCounterCollector, passive *PassiveTracker, managedSourceSet string) *DiagnosticsService {
	if capabilities == nil {
		capabilities = NewDetector(nil)
	}
	if counters == nil {
		counters = NewRuleCounterCollector(nil)
	}
	return &DiagnosticsService{
		configProvider: provider, capabilities: capabilities, counters: counters, passive: passive,
		managedSourceSet: managedSourceSet, now: time.Now,
	}
}

func (s *DiagnosticsService) Status(ctx context.Context) DiagnosticsReport {
	now := time.Now().UTC()
	if s != nil && s.now != nil {
		now = s.now().UTC()
	}
	report := DiagnosticsReport{
		CheckedAt:         now,
		FunctionalVerdict: FunctionalNotRun,
		ProductionReady:   false,
	}
	if s == nil {
		report.State = DiagnosticConfigurationErr
		report.Reasons = append(report.Reasons, "diagnostics service unavailable")
		return report
	}
	report.Capability = s.capabilities.Detect(ctx)
	report.Passive = s.passive.Snapshot(now)
	if !report.Capability.Supported {
		report.State = DiagnosticUnsupported
		report.Reasons = append(report.Reasons, "runtime PPE capability is not product-supported")
		return report
	}
	if s.configProvider == nil || s.configProvider() == nil {
		report.State = DiagnosticConfigurationErr
		report.Reasons = append(report.Reasons, "configuration snapshot unavailable")
		return report
	}
	desired, err := Compile(CompileInput{Config: s.configProvider(), Capabilities: report.Capability, ManagedSourceSet: s.managedSourceSet})
	if err != nil {
		report.State = DiagnosticConfigurationErr
		report.Reasons = append(report.Reasons, fmt.Sprintf("compile desired PPE state: %v", err))
		return report
	}
	report.DesiredGeneration = desired.Generation
	report.RuleCounters = s.counters.Collect(ctx, desired)
	if !report.RuleCounters.Available || len(report.RuleCounters.Rules) == 0 {
		report.State = DiagnosticRulesUnobserved
		report.Reasons = append(report.Reasons, "owned PPE rule counters are unavailable or no owned rule was observed")
		return report
	}
	switch report.Passive.State {
	case PassiveBidirectional:
		report.State = DiagnosticPassiveEvidence
		report.Reasons = append(report.Reasons, "passive bidirectional evidence observed; controlled functional test still required")
	case PassiveSuspectedBlind:
		report.State = DiagnosticSuspectedBlind
		report.Reasons = append(report.Reasons, "passive evidence suspects hardware-offload blindness")
	case PassiveOutgoingOnly:
		report.State = DiagnosticPassiveOutgoing
		report.Reasons = append(report.Reasons, "only outgoing passive evidence is available")
	default:
		report.State = DiagnosticCapabilityOnly
		report.Reasons = append(report.Reasons, "capability and static rule evidence only")
	}
	return report
}
