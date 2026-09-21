// PortPinStore persists the LOCAL UDP port a Proton node answered the
// pre-start handshake probe from (Nova canon, nova_wg_probe/ListenPort): a
// (local port, node port) pair answers deterministically, some pairs always
// and some never, so a random local port failed about one start in three.
// The pinned port survives restarts and profile re-issues: a node that worked
// keeps the port that worked.
package proton

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// PortPinStoreFormat is the on-disk schema version.
const PortPinStoreFormat = 1

type portPinFile struct {
	Format int               `json:"format"`
	Pins   map[string]uint16 `json:"pins"`
}

// PortPinStore is a persisted address -> local-port map.
type PortPinStore struct {
	Path string // empty = memory-only (tests)

	mu sync.Mutex
	m  map[string]uint16
}

// NewPortPinStore loads the store from path (absent/corrupt -> empty, never
// fatal: a lost pin only costs a fresh probe).
func NewPortPinStore(path string) (*PortPinStore, error) {
	s := &PortPinStore{Path: path, m: map[string]uint16{}}
	if path == "" {
		return s, nil
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var f portPinFile
	if err := json.Unmarshal(blob, &f); err != nil || f.Format != PortPinStoreFormat {
		_ = os.Rename(path, path+".corrupt")
		return s, nil
	}
	for ip, port := range f.Pins {
		if ip != "" && port != 0 {
			s.m[ip] = port
		}
	}
	return s, nil
}

// Get returns the pinned local port for an address (0 = unknown).
func (s *PortPinStore) Get(ip string) uint16 {
	if s == nil || ip == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[ip]
}

// Set records a pinned port and persists the store (best effort).
func (s *PortPinStore) Set(ip string, port uint16) {
	if s == nil || ip == "" || port == 0 {
		return
	}
	s.mu.Lock()
	if s.m[ip] == port {
		s.mu.Unlock()
		return
	}
	s.m[ip] = port
	s.mu.Unlock()
	_ = s.Save()
}

// Save writes the store atomically (0600; the file holds only public ports).
func (s *PortPinStore) Save() error {
	if s == nil || s.Path == "" {
		return nil
	}
	s.mu.Lock()
	f := portPinFile{Format: PortPinStoreFormat, Pins: make(map[string]uint16, len(s.m))}
	for k, v := range s.m {
		f.Pins[k] = v
	}
	s.mu.Unlock()
	blob, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proton-ports-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(name) }
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
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, s.Path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// Snapshot returns the current pins (sorted keys; tests/diagnostics).
func (s *PortPinStore) Snapshot() map[string]uint16 {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint16, len(s.m))
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = s.m[k]
	}
	return out
}
