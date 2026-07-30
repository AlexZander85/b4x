package discovery

import (
	"testing"
	"time"
)

func TestContextComparatorAndInvalidation(t *testing.T) {
	now := time.Unix(21000, 0)
	c := NewNetworkContext("wan-a", "eth0", "v4", 1, now)
	p := NetworkDiagnosticProfile{SchemaVersion: DiagnosticProfileSchemaVersion, ProfileID: "p", Scope: monitorScope(), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	p.Scope.NetworkContextID = c.ID
	p.Scope.ConfigGeneration = 1
	if CompareContext(p, c, now) != ContextExact {
		t.Fatal("exact context rejected")
	}
	other := c
	other.ConfigGeneration = 2
	if CompareContext(p, other, now) != ContextMismatch || !InvalidateOnContextChange(p, c, other) {
		t.Fatal("context change not invalidated")
	}
}
