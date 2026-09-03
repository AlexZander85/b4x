package ppe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

type staticCapabilityProvider struct{ report CapabilityReport }

func (s staticCapabilityProvider) Detect(context.Context) CapabilityReport { return s.report }

func TestPassiveDiagnosticsCannotEmitFunctionalPass(t *testing.T) {
	cfg := compilerConfig()
	tracker := NewPassiveTracker(8, time.Minute)
	now := time.Now()
	tracker.Observe(PassiveObservation{FlowID: "flow", Direction: PassiveOutgoing, Sequence: 1, HasSequence: true, ObservedAt: now})
	tracker.Observe(PassiveObservation{FlowID: "flow", Direction: PassiveIncoming, PayloadBytes: 10, ObservedAt: now})
	counterOutput := "1 2 200 PPE tcp -- * * 0.0.0.0/0 0.0.0.0/0 /* " + CommentTCP + " */"
	service := NewDiagnosticsService(func() *config.Config { return cfg }, staticCapabilityProvider{supportedCapabilities()}, NewRuleCounterCollector(counterRunner{output: counterOutput}), tracker, "b4_managed")
	report := service.Status(context.Background())
	if report.State != DiagnosticPassiveEvidence {
		t.Fatalf("state=%s reasons=%v", report.State, report.Reasons)
	}
	if report.FunctionalVerdict != FunctionalNotRun || report.ProductionReady || report.Passive.FunctionalConfirmation {
		t.Fatalf("passive evidence promoted to functional result: %+v", report)
	}
	if strings.EqualFold(string(report.FunctionalVerdict), "pass") {
		t.Fatal("PPE-5 emitted PASS")
	}
}

func TestDiagnosticsUnsupportedStopsBeforeStaticSuccess(t *testing.T) {
	service := NewDiagnosticsService(nil, staticCapabilityProvider{CapabilityReport{State: CapabilityUnsupported}}, nil, nil, "")
	report := service.Status(context.Background())
	if report.State != DiagnosticUnsupported || report.FunctionalVerdict != FunctionalNotRun || report.ProductionReady {
		t.Fatalf("report=%+v", report)
	}
}
