package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

const DiagnosticProfileSchemaVersion uint16 = 1

type NetworkDiagnosticProfile struct {
	SchemaVersion        uint16
	ProfileID            string
	Scope                monitor.MonitorScopeKey
	Blocking             detector.BlockingProfile
	CreatedAt, ExpiresAt time.Time
	ContentHash          string
	MigrationVersion     string
}

func (p NetworkDiagnosticProfile) Valid(now time.Time) bool {
	return p.SchemaVersion == DiagnosticProfileSchemaVersion && p.ProfileID != "" && p.Scope.Valid() && p.Blocking.Valid() && p.Blocking.Scope == p.Scope && !p.CreatedAt.IsZero() && (p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt)) && p.ContentHash != ""
}
func NewNetworkDiagnosticProfile(blocking detector.BlockingProfile, expires time.Time, now time.Time) (NetworkDiagnosticProfile, error) {
	if !blocking.Valid() {
		return NetworkDiagnosticProfile{}, errors.New("blocking profile is not ready")
	}
	p := NetworkDiagnosticProfile{SchemaVersion: DiagnosticProfileSchemaVersion, ProfileID: blocking.ProfileID, Scope: blocking.Scope, Blocking: blocking, CreatedAt: now, ExpiresAt: expires, MigrationVersion: "ddi-v1"}
	raw, _ := json.Marshal(struct {
		Version uint16
		ID      string
		Scope   monitor.MonitorScopeKey
		Hash    string
	}{p.SchemaVersion, p.ProfileID, p.Scope, blocking.ContentHash})
	h := sha256.Sum256(raw)
	p.ContentHash = hex.EncodeToString(h[:])
	return p, nil
}
func (p NetworkDiagnosticProfile) Redacted() map[string]any {
	return map[string]any{"schema_version": p.SchemaVersion, "profile_id": p.ProfileID, "scope": p.Scope, "content_hash": p.ContentHash, "created_at": p.CreatedAt, "expires_at": p.ExpiresAt, "migration_version": p.MigrationVersion}
}
