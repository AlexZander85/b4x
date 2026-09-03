package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/lab"
)

func newClientHelloLabTestAPI(t *testing.T) (*API, *http.ServeMux, *atomic.Pointer[config.Config]) {
	t.Helper()
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.ConfigPath = ""
	cfg.System.Classifier.Runtime.ClientHelloLab.CaptureDurationSeconds = 1
	var ptr atomic.Pointer[config.Config]
	ptr.Store(&cfg)
	mux := http.NewServeMux()
	api := &API{cfgPtr: &ptr, mux: mux}
	api.RegisterClientHelloLabAPI()
	return api, mux, &ptr
}

func startTestLabController(t *testing.T) *lab.SessionController {
	t.Helper()
	controller := lab.NewSessionController(nil)
	SetClientHelloSessionController(controller)
	SetClientHelloCatalog(lab.NewMemoryRetention(64))
	t.Cleanup(func() {
		controller.Stop()
		SetClientHelloSessionController(nil)
	})
	return controller
}

func postLab(t *testing.T, mux *http.ServeMux, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, reader))
	return rr
}

func TestClientHelloLabStartStopStatusLifecycle(t *testing.T) {
	_, mux, _ := newClientHelloLabTestAPI(t)
	startTestLabController(t)

	rr := postLab(t, mux, "/api/lab/clienthello/start", map[string]interface{}{
		"client_ip": "192.168.1.50", "duration_seconds": 1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", rr.Code, rr.Body.String())
	}
	var start clientHelloStartResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &start); err != nil {
		t.Fatal(err)
	}
	if !start.Success || start.SessionID == "" || start.State != string(lab.SessionRunning) {
		t.Fatalf("bad start response: %+v", start)
	}

	// Concurrent start must conflict.
	rr = postLab(t, mux, "/api/lab/clienthello/start", map[string]interface{}{"client_ip": "192.168.1.50"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("second start status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/lab/clienthello/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var statusResp clientHelloStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &statusResp); err != nil {
		t.Fatal(err)
	}
	state := statusResp.Status.(map[string]interface{})["state"]
	if state != string(lab.SessionRunning) {
		t.Fatalf("expected running, got %v", state)
	}

	rr = postLab(t, mux, "/api/lab/clienthello/stop", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("stop status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestClientHelloLabStartRequiresFilter(t *testing.T) {
	_, mux, _ := newClientHelloLabTestAPI(t)
	startTestLabController(t)

	rr := postLab(t, mux, "/api/lab/clienthello/start", map[string]interface{}{})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("start without filter status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = postLab(t, mux, "/api/lab/clienthello/start", map[string]interface{}{"client_ip": "not-an-ip"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("start with bad ip status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = postLab(t, mux, "/api/lab/clienthello/start", map[string]interface{}{"client_mac": "zz:zz"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("start with bad mac status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestClientHelloLabProfilesAndMethodGuard(t *testing.T) {
	_, mux, _ := newClientHelloLabTestAPI(t)
	startTestLabController(t)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/lab/clienthello", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("profiles status=%d body=%s", rr.Code, rr.Body.String())
	}
	// PUT on start path is not allowed.
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/lab/clienthello/start", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT start status=%d", rr.Code)
	}
}

func TestClientHelloLabUnavailableWithoutController(t *testing.T) {
	_, mux, _ := newClientHelloLabTestAPI(t)
	SetClientHelloSessionController(nil)
	t.Cleanup(func() { SetClientHelloSessionController(nil) })

	rr := postLab(t, mux, "/api/lab/clienthello/start", map[string]interface{}{"client_ip": "192.168.1.50"})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("start without controller status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/lab/clienthello/status", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status without controller status=%d", rr.Code)
	}
}

func TestClientHelloLabCapturePublishesProfile(t *testing.T) {
	_, mux, _ := newClientHelloLabTestAPI(t)
	controller := startTestLabController(t)

	rr := postLab(t, mux, "/api/lab/clienthello/start", map[string]interface{}{
		"client_ip": "192.168.1.50", "duration_seconds": 1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", rr.Code, rr.Body.String())
	}
	// Wait for the capture to time out and complete.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if controller.Status().State != lab.SessionRunning {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if controller.Status().State != lab.SessionCompleted {
		t.Fatalf("session did not complete: %s", controller.Status().State)
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/lab/clienthello", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("profiles status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp clientHelloProfilesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success {
		t.Fatal("profiles response must succeed")
	}
}
