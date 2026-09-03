// Pending-registration persistence (M3-06 partial-save). Cloudflare mints the
// device token exactly once, in the POST /reg response, BEFORE the device key is
// pinned (PATCH) and the config fetched (GET). Persisting that interim state
// immediately after POST means a crash or network cut cannot lose the token
// forever: the reconciler resumes the PATCH+GET on the next Ensure instead of
// minting a brand-new (orphaned-on-the-CF-side) device.
package transportwarp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	// ErrPendingAbsent is returned by (*PendingStore).Load when no pending
	// registration has been written yet (the common, clean path).
	ErrPendingAbsent = errors.New("transportwarp: no pending registration")
	// ErrPendingCorrupt reports a pending file that was unreadable; like an
	// identity file, a corrupt pending is quarantined (*.corrupt) rather than
	// silently dropped — it is proof an interim token existed.
	ErrPendingCorrupt = errors.New("transportwarp: pending registration file unreadable (quarantined)")
)

// PendingStore persists one in-progress registration atomically (tmp + 0600 +
// fsync + rename, the same discipline as IdentityStore). It lives beside the
// committed identity (same directory), never in /tmp.
type PendingStore struct {
	// Path is the full path of the pending file.
	Path string
}

// Save writes p atomically. Secrets (Token) are a 0600 file.
func (s *PendingStore) Save(p *PendingRegistration) error {
	if p == nil || p.ID == "" || p.Token == "" {
		return fmt.Errorf("%w: incomplete pending registration", ErrPendingCorrupt)
	}
	blob, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".pending-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := writeSecretFile(tmp, blob); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, s.Path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// Load reads the pending registration. Absent -> ErrPendingAbsent; corrupt ->
// quarantined and ErrPendingCorrupt.
func (s *PendingStore) Load() (*PendingRegistration, error) {
	blob, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrPendingAbsent
		}
		return nil, err
	}
	var p PendingRegistration
	if err := json.Unmarshal(blob, &p); err != nil {
		if qerr := os.Rename(s.Path, s.Path+".corrupt"); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrPendingCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrPendingCorrupt, err)
	}
	if p.ID == "" || p.Token == "" {
		return nil, fmt.Errorf("%w: empty id/token", ErrPendingCorrupt)
	}
	return &p, nil
}

// PendingAge reports how long a pending registration has been sitting. The
// reconciler uses it to expire stale pending registrations (spec: 24h) instead
// of resuming a token that the CF side has long since released.
func (s *PendingStore) PendingAge(now time.Time) (time.Duration, bool) {
	p, err := s.Load()
	if err != nil {
		return 0, false
	}
	if p.CreatedAt.IsZero() {
		return 0, false
	}
	return now.Sub(p.CreatedAt), true
}

// Clear removes the pending file (after the registration committed, or after a
// best-effort DELETE of an irrecoverable orphan). Absence is idempotent.
func (s *PendingStore) Clear() error {
	err := os.Remove(s.Path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
