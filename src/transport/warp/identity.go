// Device identity lifecycle storage (design §5; addendum v1.2 §9 enrollment
// transaction). The identity is the MASQUE device record returned by the
// Cloudflare registration API plus the local key material it pins:
//
//	POST /v0a4471/reg        -> id, token, account (token ONLY here; research
//	                            warp-reg-gw: losing the token is unrecoverable)
//	PATCH /reg/{id}          -> switches the device to secp256r1 + masque
//	GET  /reg/{id}           -> config: peers[0].public_key pin, interface
//	                            addresses, client_id
//
// Storage rules (z2k field lessons #4/#8, Aether account.rs):
//   - JSON on disk with mode 0600, written atomically (tmp + fsync + rename),
//     so a crash can never leave a half-written identity;
//   - a corrupt file is quarantined as *.corrupt and reported for
//     reprovisioning — never silently deleted (partial state is evidence);
//   - validation re-derives every security-relevant field (key parses, pin
//     digest matches) so a tampered or truncated file cannot reach the engine.
package transportwarp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// IdentityFormatVersion bumps on any incompatible change to the file schema.
// Load refuses other versions instead of guessing.
const IdentityFormatVersion = 1

var (
	ErrIdentityAbsent  = errors.New("transportwarp: no stored identity")
	ErrIdentityCorrupt = errors.New("transportwarp: stored identity file unreadable (quarantined)")
	ErrIdentityInvalid = errors.New("transportwarp: identity failed field validation")
)

// Identity is one enrolled MASQUE device. Token and PrivateKey are secrets:
// traces must carry only ID / PinDigest / redacted hashes.
type Identity struct {
	Format int `json:"format"`

	ID    string `json:"id"`
	Token string `json:"token"`

	AccountType string `json:"account_type,omitempty"`
	License     string `json:"license,omitempty"`

	// PrivateKey is base64(SEC1-DER) ECDSA P-256 (tlsconf.go format shared
	// with usque/warp-reg-gw state files).
	PrivateKey string `json:"private_key"`
	// PinPEM is peers[0].public_key from the registration response — the
	// endpoint trust anchor used by PrepareTLSConfig.
	PinPEM string `json:"pin_pem"`
	// PinDigest caches PinDigest(pin); Validate recomputes and compares.
	PinDigest string `json:"pin_digest"`

	AssignedV4 string `json:"assigned_v4"`
	AssignedV6 string `json:"assigned_v6,omitempty"`
	ClientID   string `json:"client_id,omitempty"` // base64, 3 bytes when present

	// EndpointHint carries peers[0].endpoint.v4 verbatim when the API
	// returns one (often hostname:port form). Endpoint SELECTION belongs to
	// discovery (E4) over the versioned catalog; this is telemetry only.
	EndpointHint string `json:"endpoint_hint,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is a renewal hook (Aether cert renewal pattern). MASQUE
	// identities normally have no server-side expiry (zero value); the
	// reconciler treats non-zero ExpiresAt within RenewWindow as renew-due.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Validate re-derives all security-relevant fields (design E2 "validate
// fields" gate of the enrollment transaction).
func (id *Identity) Validate() error {
	if id == nil {
		return fmt.Errorf("%w: nil", ErrIdentityInvalid)
	}
	if id.Format != IdentityFormatVersion {
		return fmt.Errorf("%w: format %d", ErrIdentityInvalid, id.Format)
	}
	if id.ID == "" || id.Token == "" {
		return fmt.Errorf("%w: empty id/token", ErrIdentityInvalid)
	}
	priv, err := ParseClientKeyB64(id.PrivateKey)
	if err != nil {
		return fmt.Errorf("%w: private key: %v", ErrIdentityInvalid, err)
	}
	pin, digest, err := ParsePublicKeyPEM(id.PinPEM)
	if err != nil {
		return fmt.Errorf("%w: pin: %v", ErrIdentityInvalid, err)
	}
	_ = priv // parsed == valid
	if digest != id.PinDigest || PinDigest(pin) != id.PinDigest {
		return fmt.Errorf("%w: pin digest mismatch", ErrIdentityInvalid)
	}
	// Family-safe check (BLOCKER B-1, decision D1). The CF API contract for
	// config.interface.addresses.v4 is dotted-quad. Any other string — a v6
	// literal ("::1"/"2606:4700::1"), a 4-in-6 form ("::ffff:203.0.113.7") or
	// garbage — is an anomaly and must be rejected fail-closed BEFORE any path
	// reaches netip.Addr.As4() (which panics on non-IPv4).
	v4, err := netip.ParseAddr(id.AssignedV4)
	if err != nil || !v4.IsValid() || !v4.Is4() {
		return fmt.Errorf("%w: assigned_v4 %q", ErrIdentityInvalid, id.AssignedV4)
	}
	return nil
}

// NeedsRenewal reports whether the identity enters its renewal window
// (Aether: renew 7 days before expiry; zero expiry never renews).
func (id *Identity) NeedsRenewal(now time.Time, window time.Duration) bool {
	if id == nil || id.ExpiresAt.IsZero() {
		return false
	}
	return !now.Add(window).Before(id.ExpiresAt)
}

// IdentityStore persists one Identity atomically at Path.
type IdentityStore struct {
	Path string
}

// Save writes ident atomically: temp file in the same directory, chmod 0600,
// fsync, rename over the target. A failure anywhere leaves the previous
// generation untouched (enrollment transaction COMMIT semantics).
func (s *IdentityStore) Save(ident *Identity) error {
	if ident == nil {
		return fmt.Errorf("%w: nil", ErrIdentityInvalid)
	}
	ident.Format = IdentityFormatVersion
	blob, err := json.MarshalIndent(ident, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".identity-*.tmp")
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

// Load reads and fully validates the stored identity. Missing file ->
// ErrIdentityAbsent (clean first-provision path). Unreadable/corrupt ->
// quarantined to Path+".corrupt" and ErrIdentityCorrupt returned; callers
// must treat that as "reprovision allowed".
func (s *IdentityStore) Load() (*Identity, error) {
	blob, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrIdentityAbsent
		}
		return nil, err
	}
	var ident Identity
	if err := json.Unmarshal(blob, &ident); err != nil {
		if qerr := s.Quarantine(); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrIdentityCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrIdentityCorrupt, err)
	}
	if err := ident.Validate(); err != nil {
		if qerr := s.Quarantine(); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrIdentityCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrIdentityCorrupt, err)
	}
	return &ident, nil
}

// Quarantine renames the current file to *.corrupt (replacing any earlier
// quarantine). Evidence survives for forensics; the store becomes absent.
func (s *IdentityStore) Quarantine() error {
	return os.Rename(s.Path, s.Path+".corrupt")
}

// writeSecretFile performs write+chmod+sync+close on an open temp file.
func writeSecretFile(f *os.File, blob []byte) error {
	if _, err := f.Write(blob); err != nil {
		return err
	}
	// Best-effort on platforms without POSIX modes (Windows): the production
	// target is Linux where 0600 is mandatory for secret files.
	_ = f.Chmod(0o600)
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
