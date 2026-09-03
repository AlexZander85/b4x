package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daniellavrushin/b4/capture/ppe"
)

type staticPPEProvider struct{ report ppe.CapabilityReport }

func (s staticPPEProvider) Detect(context.Context) ppe.CapabilityReport { return s.report }

func TestCaptureOffloadCapabilitiesReadOnlyEndpoint(t *testing.T) {
	api := &API{mux: http.NewServeMux(), ppeCapabilities: staticPPEProvider{report: ppe.CapabilityReport{State: ppe.CapabilityPartial}}}
	api.RegisterCaptureOffloadAPI()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capture/offload/capabilities", nil)
	res := httptest.NewRecorder()
	api.mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	var report ppe.CapabilityReport
	if err := json.NewDecoder(res.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.State != ppe.CapabilityPartial {
		t.Fatalf("state=%s", report.State)
	}
}

func TestCaptureOffloadCapabilitiesRejectsMutation(t *testing.T) {
	api := &API{mux: http.NewServeMux()}
	api.RegisterCaptureOffloadAPI()
	res := httptest.NewRecorder()
	api.mux.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/api/v1/capture/offload/capabilities", nil))
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", res.Code)
	}
}

type staticPPEStatusProvider struct{ report ppe.DiagnosticsReport }

func (s staticPPEStatusProvider) Status(context.Context) ppe.DiagnosticsReport { return s.report }

func TestCaptureOffloadStatusNeverPromotesPassiveEvidence(t *testing.T) {
	api := &API{mux: http.NewServeMux(), ppeStatus: staticPPEStatusProvider{report: ppe.DiagnosticsReport{
		State: ppe.DiagnosticPassiveEvidence, FunctionalVerdict: ppe.FunctionalNotRun, ProductionReady: false,
	}}}
	api.RegisterCaptureOffloadAPI()
	res := httptest.NewRecorder()
	api.mux.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/capture/offload/status", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	var report ppe.DiagnosticsReport
	if err := json.NewDecoder(res.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.FunctionalVerdict != ppe.FunctionalNotRun || report.ProductionReady {
		t.Fatalf("passive status promoted: %+v", report)
	}
}
