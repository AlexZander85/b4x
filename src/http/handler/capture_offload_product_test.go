package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/capture/ppe"
)

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
