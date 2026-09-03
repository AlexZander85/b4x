package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/geodat"
)

func TestHandleGeodatSources(t *testing.T) {
	cfg := config.NewConfig()
	api := &API{
		cfgPtr:         testCfgPtr(&cfg),
		geodataManager: geodat.NewGeodataManager("", ""),
	}
	mux := http.NewServeMux()
	api.mux = mux
	api.RegisterGeodatApi()

	t.Run("GET returns sources", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/geodat/sources", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}

		var sources []GeodatSource
		if err := json.NewDecoder(rec.Body).Decode(&sources); err != nil {
			t.Fatalf("failed to decode: %v", err)
		}

		if len(sources) == 0 {
			t.Error("expected at least one source")
		}

		// Check first source has required fields
		if sources[0].Name == "" || sources[0].GeositeURL == "" || sources[0].GeoipURL == "" {
			t.Error("source missing required fields")
		}
	})

	t.Run("POST not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/geodat/sources", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rec.Code)
		}
	})
}

func TestHandleFileInfo(t *testing.T) {
	cfg := config.NewConfig()
	api := &API{
		cfgPtr:         testCfgPtr(&cfg),
		geodataManager: geodat.NewGeodataManager("", ""),
	}
	mux := http.NewServeMux()
	api.mux = mux
	api.RegisterGeodatApi()

	t.Run("missing path parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/geodat/info", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/geodat/info?path=/nonexistent/file.dat", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}

		var resp map[string]interface{}
		json.NewDecoder(rec.Body).Decode(&resp)

		if resp["exists"] != false {
			t.Error("expected exists=false for nonexistent file")
		}
	})

	t.Run("existing file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.dat")
		os.WriteFile(tmpFile, []byte("test"), 0644)

		req := httptest.NewRequest(http.MethodGet, "/api/geodat/info?path="+tmpFile, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}

		var resp map[string]interface{}
		json.NewDecoder(rec.Body).Decode(&resp)

		if resp["exists"] != true {
			t.Error("expected exists=true")
		}
		if resp["size"].(float64) != 4 {
			t.Errorf("expected size=4, got %v", resp["size"])
		}
	})

	t.Run("POST not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/geodat/info?path=/tmp/test", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rec.Code)
		}
	})
}

func TestHandleGeodatDownload_Validation(t *testing.T) {
	cfg := config.NewConfig()
	api := &API{
		cfgPtr:         testCfgPtr(&cfg),
		geodataManager: geodat.NewGeodataManager("", ""),
	}
	mux := http.NewServeMux()
	api.mux = mux
	api.RegisterGeodatApi()

	t.Run("missing fields", func(t *testing.T) {
		body := `{"geosite_url": "http://example.com/geosite.dat"}`
		req := httptest.NewRequest(http.MethodPost, "/api/geodat/download", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing fields, got %d", rec.Code)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/geodat/download", strings.NewReader("not json"))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
		}
	})

	t.Run("GET not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/geodat/download", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rec.Code)
		}
	})
}
