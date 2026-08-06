package serviceprofile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/serviceprofile/schema"
)

func testManifest() schema.Manifest {
	return schema.Manifest{SchemaVersion: 1, ID: "myprofile", Name: "My Profile", Classification: "custom", Components: []schema.Component{{ID: "web", Delivery: schema.DirectStrategy, Execution: schema.ExecutionObserve, Targets: []schema.Target{{Name: "web", Role: "primary", Domains: []string{"app.example.com"}}}}}}
}

func TestExportImportRoundTrip(t *testing.T) {
	m := testManifest()
	data, err := Export(m, "https://github.com/AlexZander85/b4x")
	if err != nil {
		t.Fatal(err)
	}
	var e ExportEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	if !e.SecretsRedacted {
		t.Fatal("export must be marked secrets_redacted=true (SP-12, SP 22)")
	}
	got, err := Import(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.SafetyHash() != m.SafetyHash() {
		t.Fatalf("round-trip changed manifest: %s != %s", got.SafetyHash(), m.SafetyHash())
	}
}

func TestExportRequiresProvenance(t *testing.T) {
	if _, err := Export(testManifest(), "  "); err == nil {
		t.Fatal("export without provenance must fail (SP-12 provenance report)")
	}
}

func TestImportRejectsUnredactedPack(t *testing.T) {
	data, err := Export(testManifest(), "prov")
	if err != nil {
		t.Fatal(err)
	}
	var e ExportEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	e.SecretsRedacted = false
	tampered, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(tampered); err == nil {
		t.Fatal("import of non-redacted pack must be rejected (SP-12)")
	}
}

func TestImportRejectsMissingProvenance(t *testing.T) {
	data, _ := Export(testManifest(), "prov")
	var e ExportEnvelope
	_ = json.Unmarshal(data, &e)
	e.Provenance = ""
	tampered, _ := json.Marshal(e)
	if _, err := Import(tampered); err == nil {
		t.Fatal("import without provenance must be rejected (SP-12)")
	}
}

func TestImportRejectsInvalidManifest(t *testing.T) {
	data, _ := Export(testManifest(), "prov")
	var e ExportEnvelope
	_ = json.Unmarshal(data, &e)
	e.Manifest.Name = "" // violates schema validation
	tampered, _ := json.Marshal(e)
	if _, err := Import(tampered); err == nil {
		t.Fatal("import of schema-invalid manifest must be rejected")
	}
}

func TestForkManagedProfile(t *testing.T) {
	m := testManifest()
	f, err := ForkManagedProfile(m, "myprofile-fork", "local-user")
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != "myprofile-fork" {
		t.Fatalf("fork id: %s", f.ID)
	}
	if f.Provenance.Source != "forked" || !strings.Contains(f.Provenance.Signer, "local-user") || f.Provenance.Official {
		t.Fatalf("fork provenance must record fork origin, got %+v", f.Provenance)
	}
	// Source profile untouched.
	if m.ID != "myprofile" {
		t.Fatal("fork must not mutate the source manifest")
	}
	// Forked manifest must be fully compilable/valid.
	if _, err := Compile(f, CompileOptions{}); err != nil {
		t.Fatalf("forked manifest must compile: %v", err)
	}
}

func TestForkRequiresNewIDAndAuthor(t *testing.T) {
	if _, err := ForkManagedProfile(testManifest(), "", "user"); err == nil {
		t.Fatal("fork without new id must fail")
	}
	if _, err := ForkManagedProfile(testManifest(), "id", "  "); err == nil {
		t.Fatal("fork without author must fail")
	}
}
