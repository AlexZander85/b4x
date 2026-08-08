package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
)

// fakePPEController records the candidate passed to ApplyConfig without
// touching real firewall state, so the HTTP mutation path can be exercised.
type fakePPEController struct {
	applied *config.Config
}

func (f *fakePPEController) Snapshot(context.Context) ppe.ProductStatus { return ppe.ProductStatus{} }
func (f *fakePPEController) ApplyConfig(_ context.Context, c *config.Config) (ppe.ProductStatus, error) {
	f.applied = c
	return ppe.ProductStatus{}, nil
}
func (f *fakePPEController) Remove(context.Context) (ppe.ProductStatus, error) {
	return ppe.ProductStatus{}, nil
}
func (f *fakePPEController) RunSelfTest(context.Context, ppe.SelfTestRequest) (ppe.CaptureVisibilityResult, error) {
	return ppe.CaptureVisibilityResult{}, nil
}
func (f *fakePPEController) SelfTestResult(string) (ppe.CaptureVisibilityResult, bool) {
	return ppe.CaptureVisibilityResult{}, false
}
func (f *fakePPEController) IssueBundle(context.Context) ppe.ProductIssueBundle {
	return ppe.ProductIssueBundle{}
}
func (f *fakePPEController) ExecuteIdempotent(_ string, operation func() (ppe.ProductStatus, error)) (ppe.ProductStatus, error) {
	return operation()
}

func TestCheckPPEGeneration(t *testing.T) {
	status := ppe.ProductStatus{Desired: &ppe.DesiredState{Generation: "gen-2"}}
	if err := checkPPEGeneration(status, "gen-2"); err != nil {
		t.Fatal(err)
	}
	if err := checkPPEGeneration(status, "gen-1"); err == nil {
		t.Fatal("stale generation accepted")
	}
	if err := checkPPEGeneration(ppe.ProductStatus{}, "none"); err != nil {
		t.Fatal(err)
	}
}

func TestPPESelfTestRunIDIsBoundedAndSafe(t *testing.T) {
	got := ppeSelfTestRunID("operator key/with spaces and a very very very very very very long suffix")
	if len(got) < 3 || len(got) > 64 {
		t.Fatalf("run id length = %d: %q", len(got), got)
	}
	for _, r := range got {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		t.Fatalf("unsafe rune %q in %q", r, got)
	}
}

func TestDecodePPEMutationRequestAllowsEmptyBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/capture/offload/apply", strings.NewReader(""))
	recorder := httptest.NewRecorder()
	request, err := decodePPEMutationRequest(recorder, req)
	if err != nil || request.ExpectedGeneration != "" {
		t.Fatalf("empty mutation body: request=%+v err=%v", request, err)
	}
}

// TestPPEToggleMarksUserChosenProvenance verifies the FB-21 invariant at the
// HTTP layer: every dashboard toggle (apply or rollback) durably marks the
// policy as user-chosen, so start-time auto-integration can never flip it.
func TestPPEToggleMarksUserChosenProvenance(t *testing.T) {
	cfg := config.NewConfig()
	cfg.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	controller := &fakePPEController{}
	api := &API{cfgPtr: testCfgPtr(&cfg), ppeProduct: controller}

	applyReq := httptest.NewRequest("POST", "/api/v1/capture/offload/apply", strings.NewReader(`{}`))
	applyReq.Header.Set("Idempotency-Key", "apply-1")
	applyRec := httptest.NewRecorder()
	api.handleCaptureOffloadApply(applyRec, applyReq)
	if applyRec.Code != http.StatusOK {
		t.Fatalf("apply status = %d, body = %s", applyRec.Code, applyRec.Body.String())
	}
	applyCfg := api.getCfg()
	capture := applyCfg.System.Classifier.Runtime.Capture
	if capture.OffloadPolicy != config.OffloadPolicyExclude {
		t.Errorf("policy after apply = %q, want exclude", capture.OffloadPolicy)
	}
	if !capture.OffloadPolicyUserChosen {
		t.Error("apply must set user-chosen provenance (FB-21)")
	}

	rollbackReq := httptest.NewRequest("POST", "/api/v1/capture/offload/rollback", strings.NewReader(`{}`))
	rollbackReq.Header.Set("Idempotency-Key", "rollback-1")
	rollbackRec := httptest.NewRecorder()
	api.handleCaptureOffloadRollback(rollbackRec, rollbackReq)
	if rollbackRec.Code != http.StatusOK {
		t.Fatalf("rollback status = %d, body = %s", rollbackRec.Code, rollbackRec.Body.String())
	}
	rollbackCfg := api.getCfg()
	capture = rollbackCfg.System.Classifier.Runtime.Capture
	if capture.OffloadPolicy != config.OffloadPolicyDetect {
		t.Errorf("policy after rollback = %q, want detect", capture.OffloadPolicy)
	}
	if !capture.OffloadPolicyUserChosen {
		t.Error("rollback must keep user-chosen provenance (FB-21)")
	}
}
