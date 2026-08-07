package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/discovery"
	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/lab"
)

func compileTestAPI(t *testing.T) (*API, *http.ServeMux) {
	t.Helper()
	api, mux, _ := newClientHelloLabTestAPI(t)
	catalog := discovery.NewFakeProfileCatalog(discovery.MaxFakeCatalogEntries)
	SetFakeProfileCatalog(catalog)
	t.Cleanup(func() { SetFakeProfileCatalog(nil) })
	return api, mux
}

func rawHelloBase64(t *testing.T) string {
	t.Helper()
	raw := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestClientHelloCompilePreviewNotCommitted(t *testing.T) {
	_, mux := compileTestAPI(t)

	rr := postLab(t, mux, "/api/lab/clienthello/compile", map[string]interface{}{
		"raw_hello":       rawHelloBase64(t),
		"mode":            "fingerprint-preserving",
		"replacement_sni": "y.t",
		"ip_family":       "ipv4",
		"mtu":             1500,
		"seed":            42,
		"provenance":      "stage-26-handler-test",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("compile status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp clientHelloCompileResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success {
		t.Fatalf("compile failed: %+v", resp)
	}
	if resp.Committed {
		t.Fatal("preview-only compile must not commit")
	}
	if resp.Profile.Active {
		t.Fatal("compiled profile must never be active from the compiler")
	}
	if resp.Profile.ID == "" || resp.Profile.SourceArtifactID == "" || resp.Profile.SHA256 == "" {
		t.Fatalf("compiled profile incomplete: %+v", resp.Profile)
	}
	if resp.ChangeReport.Validation != "valid" || !resp.ChangeReport.Changed {
		t.Fatalf("change report incomplete: %+v", resp.ChangeReport)
	}
	// Preview must not touch the catalog.
	if catalog := FakeProfileCatalog(); catalog == nil || len(catalog.Profiles()) != 0 {
		t.Fatalf("preview must not commit to catalog, got %d profiles", len(catalog.Profiles()))
	}
}

func TestClientHelloCompileCommitRequiresLicenseReview(t *testing.T) {
	_, mux := compileTestAPI(t)

	// Commit without license review is rejected.
	rr := postLab(t, mux, "/api/lab/clienthello/compile", map[string]interface{}{
		"raw_hello":         rawHelloBase64(t),
		"mode":              "fingerprint-preserving",
		"replacement_sni":   "y.t",
		"ip_family":         "ipv4",
		"seed":              42,
		"commit_to_catalog": true,
		"kind":              "generated-neutral-tls",
		"source":            "operator-lab",
		"provenance":        "stage-26-handler-test",
		"license":           "MIT",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("commit without license_reviewed status=%d body=%s", rr.Code, rr.Body.String())
	}
	if catalog := FakeProfileCatalog(); catalog == nil || len(catalog.Profiles()) != 0 {
		t.Fatal("rejected commit must not touch the catalog")
	}

	// Commit with license review succeeds and records the profile.
	rr = postLab(t, mux, "/api/lab/clienthello/compile", map[string]interface{}{
		"raw_hello":         rawHelloBase64(t),
		"mode":              "fingerprint-preserving",
		"replacement_sni":   "y.t",
		"ip_family":         "ipv4",
		"seed":              42,
		"commit_to_catalog": true,
		"kind":              "generated-neutral-tls",
		"source":            "operator-lab",
		"provenance":        "stage-26-handler-test",
		"license":           "MIT",
		"license_reviewed":  true,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("commit status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp clientHelloCompileResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Committed {
		t.Fatal("expected committed=true")
	}
	catalog := FakeProfileCatalog()
	profiles := catalog.Profiles()
	if len(profiles) != 1 {
		t.Fatalf("catalog profiles=%d, want 1", len(profiles))
	}
	if profiles[0].ID != resp.Profile.ID {
		t.Fatalf("catalog id=%q want %q", profiles[0].ID, resp.Profile.ID)
	}
	if profiles[0].Active {
		t.Fatal("catalog entry must not be auto-promoted")
	}
	if !profiles[0].LicenseReviewed || profiles[0].License != "MIT" {
		t.Fatalf("license not recorded: %+v", profiles[0])
	}

	// Compiled profiles endpoint lists the committed entry.
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/lab/clienthello/compiled", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("compiled list status=%d body=%s", rr.Code, rr.Body.String())
	}
	var list compiledProfilesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if !list.Success || list.Count != 1 || len(list.Profiles) != 1 {
		t.Fatalf("bad compiled list: %+v", list)
	}
}

func TestClientHelloCompileInvalidInputs(t *testing.T) {
	_, mux := compileTestAPI(t)

	cases := []struct {
		name string
		body map[string]interface{}
	}{
		{"missing raw", map[string]interface{}{"mode": "fingerprint-preserving"}},
		{"bad base64", map[string]interface{}{"raw_hello": "!!!not-base64!!!", "mode": "fingerprint-preserving"}},
		{"unknown mode", map[string]interface{}{"raw_hello": rawHelloBase64(t), "mode": "no-such-mode"}},
		{"invalid replacement sni", map[string]interface{}{"raw_hello": rawHelloBase64(t), "mode": "fingerprint-preserving", "replacement_sni": "bad sni with spaces"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := postLab(t, mux, "/api/lab/clienthello/compile", tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestClientHelloCompileMethodGuard(t *testing.T) {
	_, mux := compileTestAPI(t)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/lab/clienthello/compile", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET compile status=%d, want 405", rr.Code)
	}
}

// TestClientHelloCrossCatalogWorkflow verifies the production scenario end to
// end: capture retention and the compiled profile catalog stay separate, the
// capture workflow never promotes anything, and both APIs stay privacy-safe
// (no raw bytes, no compiled bytes in any JSON response).
func TestClientHelloCrossCatalogWorkflow(t *testing.T) {
	_, mux := compileTestAPI(t)
	startTestLabController(t)

	// 1. Seed the capture retention the way a completed NFQ capture session
	//    would: one privacy-safe metadata profile for an eligible client.
	//    The retention API itself is covered by lab/session_test.go; here we
	//    only need the capture side populated for the cross-catalog checks.
	raw := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	captured := lab.ClientHelloProfile{
		ID:             "captured-test-1",
		FlowID:         "f-1",
		ClientID:       "client-1",
		IPFamily:       "ipv4",
		HelloHash:      hash,
		ObservedDomain: "api.youtube.com",
		RawSize:        len(raw),
		SHA256:         hash,
		PrivacyState:   "privacy-safe",
		PrivacySafe:    true,
	}
	if err := clientHelloCatalog.Load().Store(captured); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/lab/clienthello", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("profiles status=%d body=%s", rr.Code, rr.Body.String())
	}
	var captures clientHelloProfilesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &captures); err != nil {
		t.Fatal(err)
	}
	if !captures.Success || len(captures.Profiles) != 1 {
		t.Fatalf("expected 1 captured profile, got %+v", captures)
	}
	if !captures.Profiles[0].PrivacySafe || captures.Profiles[0].PrivacyState == "" {
		t.Fatalf("captured profile privacy fields invalid: %+v", captures.Profiles[0])
	}

	// 2. Compile with the captured hello as explicit raw source (the operator
	//    supplies raw bytes; capture retention never stores them), preview
	//    only, then commit with license review.
	capturedProfile := captures.Profiles[0]
	rr = postLab(t, mux, "/api/lab/clienthello/compile", map[string]interface{}{
		"raw_hello":          rawHelloBase64(t),
		"source_artifact_id": capturedProfile.ID,
		"mode":               "fingerprint-preserving",
		"replacement_sni":    "y.t",
		"ip_family":          "ipv4",
		"seed":               42,
		"commit_to_catalog":  true,
		"kind":               "generated-neutral-tls",
		"source":             "operator-lab",
		"provenance":         "stage-26-handler-test",
		"license":            "MIT",
		"license_reviewed":   true,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("compile+commit status=%d body=%s", rr.Code, rr.Body.String())
	}
	var compiledResp clientHelloCompileResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &compiledResp); err != nil {
		t.Fatal(err)
	}
	if !compiledResp.Committed {
		t.Fatal("expected committed=true")
	}
	// The compiled profile references the capture artifact and never activates.
	if compiledResp.Profile.SourceArtifactID != capturedProfile.ID || compiledResp.Profile.Active {
		t.Fatalf("compiled profile mismatch: %+v", compiledResp.Profile)
	}
	// The compiled artifact must have changed the hello (SNI rewritten).
	if compiledResp.ChangeReport.CompiledSHA256 == compiledResp.ChangeReport.OriginalSHA256 {
		t.Fatal("compile must change the hello (SNI rewrite)")
	}

	// 3. Cross-catalog invariants: capture retention unchanged, compiled
	//    catalog has exactly one entry, and it is not active.
	captures2 := clientHelloCatalog.Load().List()
	if len(captures2) != 1 {
		t.Fatalf("capture retention changed by compile workflow: %d", len(captures2))
	}
	catalogProfiles := FakeProfileCatalog().Profiles()
	if len(catalogProfiles) != 1 || catalogProfiles[0].Active {
		t.Fatalf("compiled catalog invariant broken: %+v", catalogProfiles)
	}
	// The compiled profile metadata stays privacy-safe in API responses:
	// JSON carries only metadata (hashes/ids/sizes) and the change report —
	// never compiled bytes. There is no wire field for raw or compiled bytes,
	// so the byte payload cannot be reconstructed from the API surface.
	for _, b := range []string{rr.Body.String(), getJSONBody(t, mux, "/api/lab/clienthello/compiled")} {
		if strings.Contains(b, `"raw_hello"`) || strings.Contains(b, `"bytes"`) {
			t.Fatalf("API response leaked raw or compiled bytes: %s", b)
		}
	}
}

// getJSONBody performs a GET and returns the raw JSON body for
// privacy-surface assertions.
func getJSONBody(t *testing.T, mux *http.ServeMux, path string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}
