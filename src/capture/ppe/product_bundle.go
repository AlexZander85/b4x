package ppe

import (
	"context"
	"strings"
	"time"
)

type ProductRuleSummary struct {
	Family string   `json:"family"`
	Binary string   `json:"binary"`
	Rules  []string `json:"rules,omitempty"`
}

type ProductIssueBundle struct {
	SchemaVersion    string                                   `json:"schema_version"`
	GeneratedAt      time.Time                                `json:"generated_at"`
	Platform         PlatformMetadata                         `json:"platform"`
	Capabilities     CapabilityReport                         `json:"capabilities"`
	Policy           string                                   `json:"policy"`
	ConfiguredPolicy string                                   `json:"configured_policy"`
	EffectiveMode    string                                   `json:"effective_mode"`
	Generation       string                                   `json:"generation,omitempty"`
	SourceScope      string                                   `json:"source_scope,omitempty"`
	TCPPorts         []uint16                                 `json:"tcp_ports,omitempty"`
	UDPPorts         []uint16                                 `json:"udp_ports,omitempty"`
	Rules            []ProductRuleSummary                     `json:"desired_rules,omitempty"`
	ActualRules      []ProductRuleSummary                     `json:"actual_rules,omitempty"`
	RuleErrors       []string                                 `json:"rule_errors,omitempty"`
	Counters         CounterReport                            `json:"counters"`
	Passive          PassiveSnapshot                          `json:"passive"`
	SelfTest         *CaptureVisibilityResult                 `json:"self_test,omitempty"`
	Visibility       CaptureVisibilitySnapshot                `json:"visibility"`
	Features         map[VisibilityFeature]VisibilityDecision `json:"features"`
	Reconciler       ReconcilerStatus                         `json:"reconciler"`
	Audit            []ProductAuditEvent                      `json:"audit,omitempty"`
	RawCapture       bool                                     `json:"raw_capture"`
}

func (s *ProductService) IssueBundle(ctx context.Context) ProductIssueBundle {
	status := s.Snapshot(ctx)
	bundle := ProductIssueBundle{
		SchemaVersion:    "b4-ppe-product-v1",
		GeneratedAt:      time.Now().UTC(),
		Platform:         status.Capabilities.Platform,
		Capabilities:     status.Capabilities,
		Policy:           status.Effective,
		ConfiguredPolicy: status.ConfiguredPolicy,
		EffectiveMode:    status.Effective,
		Counters:         status.Diagnostics.RuleCounters,
		Passive:          status.Diagnostics.Passive,
		SelfTest:         status.LastSelfTest,
		Visibility:       status.Visibility,
		Features:         status.Features,
		Reconciler:       status.Reconciler,
		Audit:            status.Audit,
		RawCapture:       false,
	}
	if status.Desired == nil {
		return bundle
	}
	bundle.Generation = status.Desired.Generation
	bundle.SourceScope = status.Desired.SourceScope
	bundle.TCPPorts = append([]uint16(nil), status.Desired.EffectiveTCPPorts...)
	bundle.UDPPorts = append([]uint16(nil), status.Desired.EffectiveUDPPorts...)
	for _, family := range status.Desired.Families {
		if !family.Enabled {
			continue
		}
		rules := make([]string, 0, len(family.Rules))
		for _, rule := range family.Rules {
			rules = append(rules, redactProductRule(rule, status.Desired.ManagedSourceSet))
		}
		bundle.Rules = append(bundle.Rules, ProductRuleSummary{Family: family.Family, Binary: family.Binary, Rules: rules})
	}
	bundle.ActualRules, bundle.RuleErrors = s.collectActualOwnedRules(ctx, *status.Desired)
	return bundle
}

func (s *ProductService) collectActualOwnedRules(ctx context.Context, desired DesiredState) ([]ProductRuleSummary, []string) {
	if s == nil || s.runner == nil {
		return nil, []string{"PPE command runner unavailable"}
	}
	var summaries []ProductRuleSummary
	var failures []string
	for _, family := range desired.Families {
		if !family.Enabled {
			continue
		}
		summary := ProductRuleSummary{Family: family.Family, Binary: family.Binary}
		for _, chain := range []string{"PREROUTING", "FORWARD", ChainPre, ChainFwd} {
			args := []string{"-t", "mangle", "-S", chain}
			if family.WaitSupported {
				args = append([]string{"-w"}, args...)
			}
			output, err := s.runner.Run(ctx, family.Binary, args...)
			if err != nil {
				failures = append(failures, family.Family+"/"+chain+": "+limitProductReason(err.Error()))
				continue
			}
			for _, line := range strings.Split(output, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				ownedPrivate := chain == ChainPre || chain == ChainFwd
				ownedJump := strings.Contains(line, CommentJumpPre) || strings.Contains(line, CommentJumpFwd)
				if !ownedPrivate && !ownedJump {
					continue
				}
				summary.Rules = append(summary.Rules, redactProductRule(line, desired.ManagedSourceSet))
			}
		}
		if len(summary.Rules) > 0 {
			summaries = append(summaries, summary)
		}
	}
	return summaries, failures
}

func redactProductRule(rule, managedSourceSet string) string {
	rule = strings.TrimSpace(rule)
	if managedSourceSet != "" {
		rule = strings.ReplaceAll(rule, managedSourceSet, "<managed-source-set>")
	}
	return rule
}
