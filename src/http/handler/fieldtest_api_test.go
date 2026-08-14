package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fieldtest"
)

func newFieldTestAPI(t *testing.T) *http.ServeMux {
	t.Helper()
	cfg := config.NewConfig()
	var ptr atomic.Pointer[config.Config]
	ptr.Store(&cfg)
	mux := http.NewServeMux()
	api := &API{cfgPtr: &ptr, mux: mux}
	api.RegisterFieldTestAPI()
	return mux
}

func TestCapabilitiesV1ListsUnvalidatedFeatures(t *testing.T) {
	mux := newFieldTestAPI(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, capabilitiesV1APIPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var doc capabilityDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Features) == 0 {
		t.Fatal("expected features")
	}
	if doc.Features["telegram_transparent_bridge"].DegradedReason == "" && doc.Features["telegram_transparent_bridge"].ValidatedAt != "" {
		t.Fatal("unvalidated capability must not look field-ready")
	}
	if fieldtest.Capabilities(doc.Capabilities).Allows("telegram_transparent_bridge") {
		t.Fatal("Allows must be false without validated_at")
	}
}

func TestTestSessionLifecycleRequiresHeadersAndIsIdempotent(t *testing.T) {
	mux := newFieldTestAPI(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, testSessionsV1APIPath, strings.NewReader(`{"client_id":"c1"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing headers: status=%d", rec.Code)
	}

	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, testSessionsV1APIPath, strings.NewReader(`{"client_id":"c1","target_app_id":"youtube"}`))
		req.Header.Set("Idempotency-Key", "k-1")
		req.Header.Set("X-B4-Client", "field-test")
		req.Header.Set("X-B4-Request-ID", "r-1")
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, makeReq())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var first fieldtest.TestSession
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.SessionID == "" || first.EventStream == "" {
		t.Fatalf("session: %+v", first)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, makeReq())
	if rec.Code != http.StatusOK {
		t.Fatalf("replay status=%d", rec.Code)
	}
	var second fieldtest.TestSession
	_ = json.Unmarshal(rec.Body.Bytes(), &second)
	if second.SessionID != first.SessionID {
		t.Fatalf("idempotency lost: %s vs %s", first.SessionID, second.SessionID)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, testSessionsV1APIPath+"/"+first.SessionID+"/events", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("events status=%d", rec.Code)
	}

	stop := httptest.NewRequest(http.MethodPost, testSessionsV1APIPath+"/"+first.SessionID+"/stop", nil)
	stop.Header.Set("Idempotency-Key", "k-stop")
	stop.Header.Set("X-B4-Client", "field-test")
	stop.Header.Set("X-B4-Request-ID", "r-stop")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, stop)
	if rec.Code != http.StatusOK {
		t.Fatalf("stop status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, testSessionsV1APIPath+"/"+first.SessionID+"/report", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("report status=%d", rec.Code)
	}
	var report fieldtest.SessionReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Redacted || report.Session.SessionID != first.SessionID {
		t.Fatalf("report: %+v", report)
	}
}
