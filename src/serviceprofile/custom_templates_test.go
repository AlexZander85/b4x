package serviceprofile

import (
	"testing"

	"github.com/daniellavrushin/b4/serviceprofile/schema"
)

// TestCustomTemplatesCoverSpecList pins the four §17 custom templates
// (B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM v1.6 1552-1561) so a template
// removal or rename is caught.
func TestCustomTemplatesCoverSpecList(t *testing.T) {
	builders := map[string]StarterPack{
		"custom-domain-group":               CustomDomainGroupPack("svc", "app.example.com"),
		"custom-streaming-service":          CustomStreamingServicePack("svc", "media.example.com"),
		"custom-api-plus-media":             CustomAPIPlusMediaPack("svc", "api.example.com", "media.example.com"),
		"custom-transport-required-service": CustomTransportRequiredServicePack("svc", "chat.example.com"),
	}
	for wantID, pack := range builders {
		if pack.Manifest.Classification != "custom" {
			t.Errorf("%s: classification=%s, want custom", wantID, pack.Manifest.Classification)
		}
		if _, err := Compile(pack.Manifest, CompileOptions{}); err != nil {
			t.Errorf("%s: manifest must compile: %v", wantID, err)
		}
	}
}

func TestCustomAPIPlusMediaHasTwoComponents(t *testing.T) {
	pack := CustomAPIPlusMediaPack("svc", "api.example.com", "media.example.com")
	if len(pack.Manifest.Components) != 2 {
		t.Fatalf("api+media pack must have 2 components, got %d", len(pack.Manifest.Components))
	}
	// Pack conflict guard: client-configured transport must never be handled
	// by a packet executor (SP 20 "client-configured transport не
	// обрабатывается packet executor") — delivery client-configured enforced
	// by the manifest itself and compiler integration tests.
}

func TestCustomTransportRequiredForceDefaults(t *testing.T) {
	pack := CustomTransportRequiredServicePack("t", "chat.example.com")
	if pack.Manifest.Components[0].Delivery != schema.ClientConfigured {
		t.Fatalf("transport-required template must force client-configured, got %s", pack.Manifest.Components[0].Delivery)
	}
	if pack.Manifest.Components[0].Execution != schema.ExecutionObserve {
		t.Fatalf("transport-required template must stay observe, got %s", pack.Manifest.Components[0].Execution)
	}
}

func TestTelegramPackCompilesWithClientConfigured(t *testing.T) {
	pack := TelegramPack()
	if pack.Manifest.Classification != "transport-required" {
		t.Fatalf("telegram classification: %s", pack.Manifest.Classification)
	}
	compiled, err := Compile(pack.Manifest, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Strategies) == 0 {
		t.Fatal("telegram pack must emit a strategy binding")
	}
	for _, s := range compiled.Strategies {
		if s.Delivery != string(schema.ClientConfigured) {
			t.Fatalf("telegram strategy %s must be client-configured, got %s", s.ID, s.Delivery)
		}
	}
}
