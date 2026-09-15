package tor

// Bridge storage and entry memory (design §7.1, patch-plan §3.2):
//
//   bridges.json   — the collection result (public facts, no secrets —
//                    AtomicFile canon regardless: tmp 0644 + fsync + rename,
//                    corrupt files quarantined as *.corrupt);
//   entry_memory   — the auto-ladder progress (Nova TorAutoEntryProgress):
//                    failed entries are excluded from auto until the TTL
//                    lapses, the winner becomes the ladder head; a stale
//                    record reads as empty and deletes itself.
//
// The failed-run rule (design §4.1): an unsuccessful collection KEEPS the
// previous list — the store Save happens only on a conveyor outcome the
// caller decided to persist.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BridgesFileSchema is the on-disk version of bridges.json.
const BridgesFileSchema = 1

// MaxBridgesPerKindCap is the trim ceiling per transport kind (design §4.1:
// trim-keeping-every-kind to 40 — otherwise rare kinds get crowded out,
// "a button that silently never connects").
const MaxBridgesPerKindCap = 40

// EntryMemoryTTL bounds the auto-ladder memory (design §8.3: 30 min).
const EntryMemoryTTL = 30 * time.Minute

// StoredBridge is the persistence shape of one bridge (the line stays the
// unit of exchange; transport/endpoint/fingerprint are projections).
type StoredBridge struct {
	Transport   string `json:"transport"`
	Line        string `json:"line"`
	Endpoint    string `json:"endpoint"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// BridgesFile is the bridges.json document.
type BridgesFile struct {
	Schema    int            `json:"version"`
	UpdatedAt int64          `json:"updated_at"` // epoch ms
	Source    string         `json:"source,omitempty"`
	Bridges   []StoredBridge `json:"bridges"`
	LastError string         `json:"last_error,omitempty"`
}

// BridgesStore persists the collection result at Path (AtomicFile canon).
type BridgesStore struct {
	Path string

	mu sync.Mutex
}

// NewBridgesStore builds the store for the slot layout path.
func NewBridgesStore(dataPath string) *BridgesStore {
	return &BridgesStore{Path: filepath.Join(dataPath, "bridges.json")}
}

// Load reads bridges.json; a missing file is an empty store (first run),
// a corrupt file is quarantined and reported (never a runtime crash).
func (s *BridgesStore) Load() (BridgesFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return BridgesFile{Schema: BridgesFileSchema}, nil
		}
		return BridgesFile{}, err
	}
	var f BridgesFile
	if err := json.Unmarshal(blob, &f); err != nil {
		_ = os.Rename(s.Path, s.Path+".corrupt")
		return BridgesFile{Schema: BridgesFileSchema}, fmt.Errorf("bridges store corrupt (quarantined): %w", err)
	}
	if f.Schema != BridgesFileSchema {
		_ = os.Rename(s.Path, s.Path+".corrupt")
		return BridgesFile{Schema: BridgesFileSchema}, fmt.Errorf("bridges store schema %d unsupported (quarantined)", f.Schema)
	}
	return f, nil
}

// Save writes bridges.json atomically (tmp + fsync + rename).
func (s *BridgesStore) Save(f BridgesFile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Schema == 0 {
		f.Schema = BridgesFileSchema
	}
	blob, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".bridges-*.tmp")
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
	// Public facts, no secrets — readable for field diagnostics (design
	// §7.1: "bridges.json — публичные факты").
	_ = tmp.Chmod(0o644)
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("bridges store rename: %w", err)
	}
	return nil
}

// DedupKey is the collection identity of a bridge (design §4.1:
// transport|fingerprint|endpoint).
func DedupKey(b Bridge) string {
	return b.Transport + "|" + b.Fingerprint + "|" + b.AddrPort
}

// Dedup collapses a bridge slice by DedupKey keeping the first occurrence.
func Dedup(bridges []Bridge) []Bridge {
	seen := make(map[string]bool, len(bridges))
	out := make([]Bridge, 0, len(bridges))
	for _, b := range bridges {
		k := DedupKey(b)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, b)
	}
	return out
}

// TrimKeepingEveryKind rounds the set down to cap per transport kind,
// cycling across kinds so rare transports survive (design §4.1 — the
// Nova trim canon). Order within a kind is preserved (probe-ranked lists
// stay probe-ranked).
func TrimKeepingEveryKind(bridges []Bridge, cap int) []Bridge {
	if cap <= 0 {
		cap = MaxBridgesPerKindCap
	}
	byKind := make(map[string][]Bridge)
	var kinds []string
	for _, b := range bridges {
		if _, ok := byKind[b.Transport]; !ok {
			kinds = append(kinds, b.Transport)
		}
		byKind[b.Transport] = append(byKind[b.Transport], b)
	}
	// round-robin: one bridge per kind per pass until caps exhaust —
	// every kind survives with its head, the fat kinds cap at `cap`.
	out := make([]Bridge, 0, len(bridges))
	remaining := make(map[string]int, len(kinds))
	for _, k := range kinds {
		remaining[k] = 0
	}
	for {
		progress := false
		for _, k := range kinds {
			idx := remaining[k]
			if idx < len(byKind[k]) && idx < cap {
				out = append(out, byKind[k][idx])
				remaining[k]++
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	return out
}

// EntryMemoryState is the decoded auto-ladder progress.
type EntryMemoryState struct {
	At     time.Time
	Failed []string // transports that failed in this window
	Winner string   // the transport that won ("" until one does)
}

// EntryMemory persists the auto-ladder progress at <dataPath>/entry_memory.txt:
// line 1 = epoch-ms of the window start; then "failed <transport>" lines and
// at most one "winner <transport>" line. TTL 30 min: a stale record reads
// as empty and deletes the file (Nova TorAutoEntryProgress canon).
type EntryMemory struct {
	Path string

	mu sync.Mutex
}

// NewEntryMemory builds the memory for the slot layout path.
func NewEntryMemory(dataPath string) *EntryMemory {
	return &EntryMemory{Path: filepath.Join(dataPath, "entry_memory.txt")}
}

// Load reads the memory; stale (TTL exceeded) or corrupt records read as
// empty and remove the file so the ladder starts a fresh window.
func (m *EntryMemory) Load(now func() time.Time) EntryMemoryState {
	m.mu.Lock()
	defer m.mu.Unlock()
	blob, err := os.ReadFile(m.Path)
	if err != nil {
		return EntryMemoryState{}
	}
	lines := strings.Split(strings.TrimSpace(string(blob)), "\n")
	if len(lines) < 1 {
		_ = os.Remove(m.Path)
		return EntryMemoryState{}
	}
	ms, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	if err != nil || ms <= 0 {
		_ = os.Remove(m.Path)
		return EntryMemoryState{}
	}
	at := time.UnixMilli(ms)
	if now().Sub(at) > EntryMemoryTTL {
		_ = os.Remove(m.Path)
		return EntryMemoryState{} // window lapsed: fresh ladder
	}
	st := EntryMemoryState{At: at}
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "failed "):
			st.Failed = append(st.Failed, strings.TrimSpace(strings.TrimPrefix(l, "failed ")))
		case strings.HasPrefix(l, "winner "):
			st.Winner = strings.TrimSpace(strings.TrimPrefix(l, "winner "))
		}
	}
	return st
}

// RecordFail appends a failed transport to the current window (creating
// the window when absent) and persists atomically.
func (m *EntryMemory) RecordFail(transport string, now func() time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.readLocked(now)
	st.Failed = append(st.Failed, transport)
	return m.writeLocked(st)
}

// RecordWin sets the winner (the ladder head for the next start) and
// persists atomically. A winner replaces any previous one.
func (m *EntryMemory) RecordWin(transport string, now func() time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.readLocked(now)
	st.Winner = transport
	return m.writeLocked(st)
}

// Clear removes the memory (first successful stream / manual entry change —
// design §8.3).
func (m *EntryMemory) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.Remove(m.Path)
}

func (m *EntryMemory) readLocked(now func() time.Time) EntryMemoryState {
	blob, err := os.ReadFile(m.Path)
	if err != nil {
		return EntryMemoryState{At: now()}
	}
	lines := strings.Split(strings.TrimSpace(string(blob)), "\n")
	ms, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	if err != nil || ms <= 0 || now().Sub(time.UnixMilli(ms)) > EntryMemoryTTL {
		return EntryMemoryState{At: now()}
	}
	st := EntryMemoryState{At: time.UnixMilli(ms)}
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "failed "):
			st.Failed = append(st.Failed, strings.TrimSpace(strings.TrimPrefix(l, "failed ")))
		case strings.HasPrefix(l, "winner "):
			st.Winner = strings.TrimSpace(strings.TrimPrefix(l, "winner "))
		}
	}
	return st
}

func (m *EntryMemory) writeLocked(st EntryMemoryState) error {
	var b strings.Builder
	b.WriteString(strconv.FormatInt(st.At.UnixMilli(), 10))
	b.WriteByte('\n')
	for _, f := range st.Failed {
		b.WriteString("failed ")
		b.WriteString(f)
		b.WriteByte('\n')
	}
	if st.Winner != "" {
		b.WriteString("winner ")
		b.WriteString(st.Winner)
		b.WriteByte('\n')
	}
	dir := filepath.Dir(m.Path)
	tmp, err := os.CreateTemp(dir, ".entrymemory-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
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
	if err := os.Rename(tmpName, m.Path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("entry memory rename: %w", err)
	}
	return nil
}
