// Opera device identity slot (design §1.1/§4). The SurfEasy registration is
// anonymous and per-run in the upstream clients; our red line #3 requires at
// most one device registration per router boot, so the identity persists in
// a slot file using the same transactional pattern as the WG/MASQUE stores:
// temp file, 0600, fsync, rename; corrupt files are quarantined *.corrupt,
// never deleted (evidence survives).
package opera

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity format version. Bump on incompatible shape changes.
const identityFormatVersion = 1

var (
	// ErrIdentityAbsent: slot file does not exist (fresh boot).
	ErrIdentityAbsent = errors.New("opera identity absent")
	// ErrIdentityInvalid: identity failed structural validation before save.
	ErrIdentityInvalid = errors.New("opera identity invalid")
	// ErrIdentityCorrupt: stored identity unreadable/tampered (quarantined).
	ErrIdentityCorrupt = errors.New("opera identity corrupt")
)

// Identity is the persisted SurfEasy session. Secret fields follow design
// §7.6: never logged — Redacted() strips everything credential-shaped.
type Identity struct {
	Format int `json:"format"`
	// Anonymous subscriber (email local-part is b64(32 random bytes);
	// password is derivable from the email by a public formula, hence the
	// email itself is treated as secret material too).
	SubscriberEmail    string `json:"subscriber_email"`
	SubscriberPassword string `json:"subscriber_password"`
	// Data-plane credentials: login = SHA1(device_id) capital hex,
	// password = device_password JWT issued by register_device /
	// device_generate_password.
	DeviceID     string `json:"device_id"`
	DeviceIDHash string `json:"device_id_hash"`
	DevicePassword string `json:"device_password"`
	// TOFU SPKI pins of the API channel (host -> sha256 hex), design §3.
	Pins map[string]string `json:"pins,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate checks structural integrity including the device hash derivation
// (tamper detection without any trusted hardware).
func (id *Identity) Validate() error {
	switch {
	case id == nil:
		return fmt.Errorf("%w: nil", ErrIdentityInvalid)
	case id.Format != identityFormatVersion:
		return fmt.Errorf("%w: format %d", ErrIdentityInvalid, id.Format)
	case !strings.Contains(id.SubscriberEmail, "@"):
		return fmt.Errorf("%w: subscriber email malformed", ErrIdentityInvalid)
	case id.SubscriberPassword == "":
		return fmt.Errorf("%w: subscriber password empty", ErrIdentityInvalid)
	case id.DeviceID == "":
		return fmt.Errorf("%w: device id empty", ErrIdentityInvalid)
	case id.DevicePassword == "":
		return fmt.Errorf("%w: device password empty", ErrIdentityInvalid)
	case id.DeviceIDHash != capitalHexSHA1(id.DeviceID):
		return fmt.Errorf("%w: device id hash mismatch", ErrIdentityInvalid)
	}
	for host, fp := range id.Pins {
		if host == "" || fp == "" {
			return fmt.Errorf("%w: empty pin entry", ErrIdentityInvalid)
		}
	}
	return nil
}

// Redacted returns a copy safe for logs/status views: every credential-
// shaped field (including the subscriber email — its "password" is derived
// from it by a public formula) is replaced with "[redacted]".
func (id *Identity) Redacted() *Identity {
	if id == nil {
		return nil
	}
	out := *id
	out.SubscriberEmail = "[redacted]"
	out.SubscriberPassword = "[redacted]"
	out.DeviceID = "[redacted]"
	out.DeviceIDHash = "[redacted]"
	out.DevicePassword = "[redacted]"
	pins := make(map[string]string, len(id.Pins))
	for host, fp := range id.Pins {
		if len(fp) > 12 {
			fp = fp[:12] + "…"
		}
		pins[host] = fp
	}
	out.Pins = pins
	return &out
}

// ---------------------------------------------------------------------------
// Random/hash helpers (mirror of reference randutils.go / hash.go).
// ---------------------------------------------------------------------------

// capitalHexSHA1 is the universal SurfEasy derivation: anonymous subscriber
// password and proxy login are both upper-hex(SHA-1(input)).
func capitalHexSHA1(input string) string {
	sum := sha1.Sum([]byte(input))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// ---------------------------------------------------------------------------
// Store.
// ---------------------------------------------------------------------------

// IdentityStore persists one Identity atomically at Path. The path IS the
// slot selector; nested/secondary configurations use a distinct path.
type IdentityStore struct {
	Path string
}

// Save writes the identity atomically after validation.
func (s *IdentityStore) Save(id *Identity) error {
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
	tmp, err := os.CreateTemp(dir, ".opera-id-*.tmp")
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
// ErrIdentityAbsent; unreadable/tampered -> quarantined + ErrIdentityCorrupt.
func (s *IdentityStore) Load() (*Identity, error) {
	blob, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
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
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrIdentityCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrIdentityCorrupt, err)
	}
	return &id, nil
}

// Quarantine renames the current slot to *.corrupt (evidence survives).
func (s *IdentityStore) Quarantine() error {
	return os.Rename(s.Path, s.Path+".corrupt")
}

// writeSecretFile performs write+chmod+sync+close on an open temp file
// (same discipline as transport/wg and transport/warp stores).
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
