// Last-good persistence for the seek ladder (design §5): the winning
// {endpoint, profile} pair is remembered and offered first on the next
// run. The store interface keeps storage pluggable; the file backend
// follows the identity-store transactional discipline (temp + fsync +
// rename, corrupt files quarantined).
package transportwg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Attempt identifies one successful (or recorded) seek attempt.
type Attempt struct {
	Endpoint  netip.AddrPort `json:"endpoint"`
	ProfileID string         `json:"profile_id"`
	At        time.Time      `json:"at"`
}

// LastGoodStore remembers the winning attempt.
type LastGoodStore interface {
	Get() (Attempt, bool)
	Put(a Attempt) error
}

// MemoryLastGood is the in-process implementation (tests, stateless runs).
type MemoryLastGood struct {
	mu  sync.Mutex
	val Attempt
	ok  bool
}

func (m *MemoryLastGood) Get() (Attempt, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.val, m.ok
}

func (m *MemoryLastGood) Put(a Attempt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.val, m.ok = a, true
	return nil
}

// FileLastGood persists one attempt as JSON at Path.
type FileLastGood struct {
	Path string
}

type lastGoodFile struct {
	Attempt   Attempt `json:"attempt"`
	CatalogVr int     `json:"catalog_version"`
}

var errLastGoodCorrupt = errors.New("transportwg: last-good store corrupt")

func (f FileLastGood) Get() (Attempt, bool) {
	blob, err := os.ReadFile(f.Path)
	if err != nil {
		return Attempt{}, false
	}
	var rec lastGoodFile
	if err := json.Unmarshal(blob, &rec); err != nil {
		_ = os.Rename(f.Path, f.Path+".corrupt")
		return Attempt{}, false
	}
	if rec.CatalogVr != CatalogVersion {
		return Attempt{}, false // stale catalog generation: re-seek
	}
	if !rec.Attempt.Endpoint.IsValid() || rec.Attempt.ProfileID == "" {
		return Attempt{}, false
	}
	return rec.Attempt, true
}

func (f FileLastGood) Put(a Attempt) error {
	rec := lastGoodFile{Attempt: a, CatalogVr: CatalogVersion}
	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, ".lastgood-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(blob); err != nil {
		cleanup()
		return err
	}
	_ = tmp.Chmod(0o600)
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, f.Path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("transportwg: last-good rename: %w", err)
	}
	return nil
}
