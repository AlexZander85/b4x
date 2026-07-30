package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type BlockingProfileStatus string

const (
	ProfileReady      BlockingProfileStatus = "ready"
	ProfileIncomplete BlockingProfileStatus = "incomplete"
	ProfileCancelled  BlockingProfileStatus = "cancelled"
	ProfileSuppressed BlockingProfileStatus = "suppressed"
)

type MonitorAssessmentRef struct {
	AssessmentID, RequestID string
	Scope                   monitor.MonitorScopeKey
	ConfigGeneration        uint64
}
type BlockingProfile struct {
	ProfileID    string
	Status       BlockingProfileStatus
	Scope        monitor.MonitorScopeKey
	Assessment   MonitorAssessmentRef
	Hypothesis   string
	Confidence   ConfidenceSummary
	EvidenceRefs []string
	ContentHash  string
	CompiledAt   time.Time
}

func (p BlockingProfile) Valid() bool {
	return p.ProfileID != "" && p.Status == ProfileReady && p.Scope.Valid() && p.Assessment.AssessmentID != "" && p.Assessment.RequestID != "" && p.Assessment.ConfigGeneration == p.Scope.ConfigGeneration && p.ContentHash != "" && len(p.EvidenceRefs) > 0
}

type MonitorDiagnosticResultStatus string

const (
	ResultAccepted   MonitorDiagnosticResultStatus = "accepted"
	ResultIncomplete MonitorDiagnosticResultStatus = "incomplete"
	ResultCancelled  MonitorDiagnosticResultStatus = "cancelled"
	ResultSuppressed MonitorDiagnosticResultStatus = "suppressed"
	ResultRejected   MonitorDiagnosticResultStatus = "rejected"
)

type MonitorDiagnosticResult struct {
	ResultID, AssessmentID, RequestID string
	Scope                             monitor.MonitorScopeKey
	ConfigGeneration                  uint64
	Status                            MonitorDiagnosticResultStatus
	ProfileID                         string
	EvidenceRefs                      []string
	DeliveredAt                       time.Time
	Explanation                       string
}

func (r MonitorDiagnosticResult) Valid() bool {
	return r.ResultID != "" && r.AssessmentID != "" && r.RequestID != "" && r.Scope.Valid() && r.ConfigGeneration == r.Scope.ConfigGeneration && r.Status != "" && !r.DeliveredAt.IsZero()
}

func CompileBlockingProfile(graph *EvidenceGraph, assessment MonitorAssessmentRef, hypothesis string, runComplete, authoritative bool, evidenceRefs []string, now time.Time) (BlockingProfile, MonitorDiagnosticResult, error) {
	result := MonitorDiagnosticResult{ResultID: assessment.RequestID + "/result", AssessmentID: assessment.AssessmentID, RequestID: assessment.RequestID, Scope: assessment.Scope, ConfigGeneration: assessment.ConfigGeneration, DeliveredAt: now}
	if !runComplete || !authoritative || len(evidenceRefs) == 0 {
		result.Status = ResultIncomplete
		result.Explanation = "complete authoritative ABD evidence is required"
		return BlockingProfile{}, result, nil
	}
	if graph == nil {
		result.Status = ResultRejected
		return BlockingProfile{}, result, errors.New("evidence graph required")
	}
	confidence := graph.Confidence(hypothesis)
	if confidence.Supports == 0 || confidence.Score <= 0 {
		result.Status = ResultRejected
		result.Explanation = "evidence graph has no authoritative support"
		return BlockingProfile{}, result, errors.New("insufficient authoritative evidence")
	}
	payload := struct {
		Scope      monitor.MonitorScopeKey
		Assessment MonitorAssessmentRef
		Hypothesis string
		Confidence ConfidenceSummary
		Evidence   []string
	}{assessment.Scope, assessment, hypothesis, confidence, evidenceRefs}
	raw, _ := json.Marshal(payload)
	h := sha256.Sum256(raw)
	hash := hex.EncodeToString(h[:])
	pid := "bp-" + hash[:16]
	p := BlockingProfile{ProfileID: pid, Status: ProfileReady, Scope: assessment.Scope, Assessment: assessment, Hypothesis: hypothesis, Confidence: confidence, EvidenceRefs: append([]string(nil), evidenceRefs...), ContentHash: hash, CompiledAt: now}
	result.Status = ResultAccepted
	result.ProfileID = pid
	result.EvidenceRefs = append([]string(nil), evidenceRefs...)
	result.Explanation = "authoritative complete evidence compiled; action authorization remains external"
	return p, result, nil
}
