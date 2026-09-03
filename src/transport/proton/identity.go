// Proton identity slot (design §4): ONE store at
// /opt/etc/b4/proton/identity.json following the four existing identity
// stores' canon (wg/identity.go:206-288): temp file, chmod 0600, fsync,
// rename; corrupt files are quarantined *.corrupt, never deleted; Validate
// re-derives every security-relevant field so a tampered store cannot reach
// the engine.
//
// The seed is the SINGLE secret of the whole transport: WG private key is
// always re-derived from it (crypto.go) and never persisted separately.
// Redacted() is the ONLY shape allowed into logs/status/summaries — the
// redaction rule of the program (seed/tokens never leave the package).
package proton

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// IdentityFormatVersion bumps on incompatible schema changes; Load refuses
// other versions instead of guessing.
const IdentityFormatVersion = 1

// DeviceProfile is the fabricated, install-stable device description fed to
// the anti-abuse challenge frame (design §1.3). The struct fields use the
// Nova profile names; ChallengeFrame() maps them onto the wire keys.
type DeviceProfile struct {
	Model          string   `json:"model"`
	AndroidVersion string   `json:"android_version"`
	Language       string   `json:"language"`
	RegionCode     string   `json:"region_code"`
	Timezone       string   `json:"timezone"`
	TimezoneOffset int      `json:"timezone_offset"`
	StorageBytes   float64  `json:"storage_bytes"`
	DeviceNameHash int64    `json:"device_name_hash"`
	Keyboards      []string `json:"keyboards"`
}

// Identity is one credentialless Proton enrollment plus everything the
// engine needs to rebuild the WG identity without re-registration.
type Identity struct {
	Format int `json:"format"`

	// SeedB64 is the 32-byte master seed (base64, raw std) — the SINGLE
	// secret. Everything else security-relevant derives from it.
	SeedB64 string `json:"seed"`
	// DeviceProfile persists the fabricated challenge profile — STABLE across
	// re-registrations (a per-call profile would look worse to the anti-abuse
	// layer than one constant one, Nova ProtonApi.kt:192-200).
	DeviceProfile DeviceProfile `json:"device_profile"`

	// Session material (credentialless flow). All three rotate on refresh.
	UID          string `json:"uid,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`

	// RegisteredPubPEM is the ed25519 SPKI PEM Proton accepted; Validate
	// re-derives it from the seed and compares.
	RegisteredPubPEM string `json:"registered_pub_pem"`

	// CertExpiresAt/CertRefreshAt are unix seconds. RefreshAt = ExpirationTime
	// minus the 30-day persistent margin (renew window opens).
	CertExpiresAt int64 `json:"cert_expires_at,omitempty"`
	CertRefreshAt int64 `json:"cert_refresh_at,omitempty"`

	// Optional assignments from the certificate response (design §1.8 fixes
	// the constants when the API omits them: 10.2.0.2/32 + 2a07:b944::2:2/128).
	VPNIv4 string   `json:"vpn_ipv4,omitempty"`
	VPNIv6 string   `json:"vpn_ipv6,omitempty"`
	VPNDNS []string `json:"vpn_dns,omitempty"`

	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

// Seed decodes the stored seed into its raw 32 bytes.
func (id *Identity) Seed() ([32]byte, error) {
	var seed [32]byte
	if id == nil {
		return seed, fmt.Errorf("%w: nil", ErrIdentityInvalid)
	}
	raw, err := base64.StdEncoding.DecodeString(id.SeedB64)
	if err != nil {
		return seed, fmt.Errorf("%w: seed base64: %v", ErrIdentityInvalid, err)
	}
	if len(raw) != 32 {
		return seed, fmt.Errorf("%w: seed must be 32 bytes, got %d", ErrIdentityInvalid, len(raw))
	}
	copy(seed[:], raw)
	return seed, nil
}

// Validate re-derives every security-relevant field: the seed must decode to
// 32 bytes and the registered PEM must equal the derived ed25519 SPKI PEM.
func (id *Identity) Validate() error {
	if id == nil {
		return fmt.Errorf("%w: nil", ErrIdentityInvalid)
	}
	if id.Format != 0 && id.Format != IdentityFormatVersion {
		return fmt.Errorf("%w: format %d", ErrIdentityInvalid, id.Format)
	}
	seed, err := id.Seed()
	if err != nil {
		return err
	}
	if id.RegisteredPubPEM == "" {
		return fmt.Errorf("%w: empty registered_pub_pem", ErrIdentityInvalid)
	}
	if derived := DeriveKeyPair(seed).Ed25519PubPEM; derived != id.RegisteredPubPEM {
		return fmt.Errorf("%w: registered_pub_pem does not match the derived key", ErrIdentityInvalid)
	}
	return nil
}

// RedactedIdentity is the log/status shape: no seed, no tokens — only the
// first 12 hex-ish chars of the PEM body prefix marker, cert timing and the
// fabrication timestamps.
type RedactedIdentity struct {
	Format        int           `json:"format"`
	HasSeed       bool          `json:"has_seed"`
	PubkeyPrefix  string        `json:"pubkey_prefix"`
	DeviceProfile DeviceProfile `json:"device_profile"`
	HasSession    bool          `json:"has_session"`
	CertExpiresAt int64         `json:"cert_expires_at,omitempty"`
	CertRefreshAt int64         `json:"cert_refresh_at,omitempty"`
	CreatedAt     int64         `json:"created_at"`
	UpdatedAt     int64         `json:"updated_at"`
}

// Redacted returns the log-safe projection (design §4: tokens/seed ->
// "[redacted]", outside only pubkey_prefix(12), cert_expires_at, timestamps).
func (id *Identity) Redacted() RedactedIdentity {
	if id == nil {
		return RedactedIdentity{}
	}
	_, seedErr := id.Seed()
	return RedactedIdentity{
		Format:        id.Format,
		HasSeed:       seedErr == nil,
		PubkeyPrefix:  pubkeyPrefix(id.RegisteredPubPEM),
		DeviceProfile: id.DeviceProfile,
		HasSession:    id.UID != "" && id.AccessToken != "",
		CertExpiresAt: id.CertExpiresAt,
		CertRefreshAt: id.CertRefreshAt,
		CreatedAt:     id.CreatedAt,
		UpdatedAt:     id.UpdatedAt,
	}
}

// pubkeyPrefix extracts the first 12 chars of the base64 PEM body (the fixed
// DER prefix dominates; the distinguishing tail begins right after — the
// prefix is public knowledge, nothing secret leaks).
func pubkeyPrefix(pem string) string {
	body := pem
	if i := bytes.IndexByte([]byte(pem), '\n'); i >= 0 {
		body = pem[i+1:]
	}
	if j := bytes.IndexByte([]byte(body), '\n'); j >= 0 {
		body = body[:j]
	}
	if len(body) > 12 {
		body = body[:12]
	}
	return body
}

// Touch stamps UpdatedAt (call before Save).
func (id *Identity) Touch(now time.Time) { id.UpdatedAt = now.Unix() }

// IdentityStore persists one Identity atomically at Path (the wg store's
// transactional pattern: temp file, 0600, fsync, rename; corrupt files are
// quarantined *.corrupt).
type IdentityStore struct {
	Path string
}

// Save validates and writes the identity atomically.
func (s *IdentityStore) Save(id *Identity) error {
	if id == nil {
		return fmt.Errorf("%w: nil", ErrIdentityInvalid)
	}
	id.Format = IdentityFormatVersion
	if err := id.Validate(); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proton-id-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := writeSecretFile(tmp, blob); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// Load reads and fully validates the stored identity; missing ->
// ErrIdentityAbsent; unreadable/tampered -> quarantined + ErrIdentityCorrupt;
// field-invalid -> ErrIdentityInvalid WITH quarantine (a tampered store is
// evidence, not a usable state).
func (s *IdentityStore) Load() (*Identity, error) {
	blob, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrIdentityAbsent
		}
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(blob, &id); err != nil {
		if qerr := s.Quarantine(); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrIdentityCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrIdentityCorrupt, err)
	}
	if err := id.Validate(); err != nil {
		if qerr := s.Quarantine(); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrIdentityInvalid, err, qerr)
		}
		return nil, err
	}
	return &id, nil
}

// Quarantine renames the current file to *.corrupt (evidence survives).
func (s *IdentityStore) Quarantine() error {
	return os.Rename(s.Path, s.Path+".corrupt")
}

// writeSecretFile performs write+chmod+sync+close on an open temp file (the
// shared discipline of wg/fxvpn stores).
func writeSecretFile(f *os.File, blob []byte) error {
	if _, err := f.Write(blob); err != nil {
		return err
	}
	// Best-effort on platforms without POSIX modes (Windows); production
	// target is Linux where 0600 is mandatory for secret files.
	_ = f.Chmod(0o600)
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
