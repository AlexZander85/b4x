// BLK-6 verification: the control plane now accepts action="rst" (200 and
// persisted) while unknown actions are rejected; the status payload echoes
// the effective action.
package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func adblockTestAPI(t *testing.T) (*API, *atomic.Pointer[config.Config], string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "b4.json")

	cfg := config.NewConfig()
	cfg.ConfigPath = cfgPath
	if err := cfg.SaveToFile(cfgPath); err != nil {
		t.Fatal(err)
	}

	var ptr atomic.Pointer[config.Config]
	ptr.Store(&cfg)
	api := &API{cfgPtr: &ptr, mux: http.NewServeMux()}
	return api, &ptr, cfgPath
}

func adblockConfigRequest(t *testing.T, api *API, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/adblock/config", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	api.handleAdBlockConfig(rec, req)

	var payload map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("status payload unparsable: %v (%s)", err, rec.Body.String())
		}
	}
	return rec, payload
}

func TestAdBlockConfigAcceptsRSTAction(t *testing.T) {
	api, ptr, cfgPath := adblockTestAPI(t)

	rec, payload := adblockConfigRequest(t, api, `{"action":"rst"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rst must be accepted now, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := payload["action"]; got != "rst" {
		t.Fatalf("echoed action=%v want rst", got)
	}
	if got := ptr.Load().AdBlock.Action; got != "rst" {
		t.Fatalf("live config action=%q want rst", got)
	}

	// Persisted to disk, not only in memory.
	blob, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved config.Config
	if err := json.Unmarshal(blob, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.AdBlock.Action != "rst" {
		t.Fatalf("persisted action=%q want rst", saved.AdBlock.Action)
	}

	// And back to drop.
	rec, _ = adblockConfigRequest(t, api, `{"action":"drop"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("drop must stay accepted, got %d", rec.Code)
	}
	if ptr.Load().AdBlock.Action != "drop" {
		t.Fatal("action must round-trip back to drop")
	}
}

func TestAdBlockConfigRejectsUnknownAction(t *testing.T) {
	api, ptr, _ := adblockTestAPI(t)

	rec, _ := adblockConfigRequest(t, api, `{"action":"fancy"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action must be 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := ptr.Load().AdBlock.Action; got != "" && got != "drop" {
		t.Fatalf("rejected request must not mutate config (got %q)", got)
	}
}
