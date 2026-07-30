package discovery

import (
	"testing"
	"time"
)

func TestProfileViewExplainsStaleAndSuppressed(t *testing.T) {
	now := time.Unix(25000, 0)
	p := NetworkDiagnosticProfile{SchemaVersion: DiagnosticProfileSchemaVersion, ProfileID: "p", Scope: monitorScope(), ExpiresAt: now.Add(-time.Second)}
	if ProfileView(p, now, false).Badge != BadgeStale || ProfileView(p, now, true).Badge != BadgeSuppressed {
		t.Fatal("profile view badge incorrect")
	}
}
func TestSavingsReportInvariant(t *testing.T) {
	r := SearchSavingsReport{BaselineProbes: 10, GuidedProbes: 6, SavedProbes: 4}
	if !r.Valid() {
		t.Fatal(r)
	}
}
