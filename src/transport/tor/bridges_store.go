package tor

// Bridge storage and entry memory (design §7.1, patch-plan §3.2).

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

const BridgesFileSchema = 1
const MaxBridgesPerKindCap = 40
const EntryMemoryTTL = 30 * time.Minute

type StoredBridge struct {
	Transport   string `json:"transport"`
	Line        string `json:"line"`
	Endpoint    string `json:"endpoint"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type BridgesFile struct {
	Schema    int            `json:"version"`
	UpdatedAt int64          `json:"updated_at"`
	Source    string         `json:"source,omitempty"`
	Bridges   []StoredBridge `json:"bridges"`
	LastError string         `json:"last_error,omitempty"`
}

type BridgesStore struct {
	Path string
	mu   sync.Mutex
}

func NewBridgesStore(dataPath string) *BridgesStore {
	return &BridgesStore{Path: filepath.Join(dataPath, "bridges.json")}
}

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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
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

func DedupKey(b Bridge) string {
	return b.Transport + "|" + b.Fingerprint + "|" + b.AddrPort
}

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

// EntryMemoryState carries transport-level ladder state plus an optional
// stable bridge identity. The bridge identity is diagnostic/learning data;
// the ladder continues to key on transport so existing files remain valid.
type EntryMemoryState struct {
	At           time.Time
	Failed       []string
	Winner       string
	WinnerBridge string
}

type EntryMemory struct {
	Path string
	mu   sync.Mutex
}

func NewEntryMemory(dataPath string) *EntryMemory {
	return &EntryMemory{Path: filepath.Join(dataPath, "entry_memory.txt")}
}

func (m *EntryMemory) Load(now func() time.Time) EntryMemoryState {
	m.mu.Lock()
	defer m.mu.Unlock()
	blob, err := os.ReadFile(m.Path)
	if err != nil {
		return EntryMemoryState{}
	}
	return m.parseLocked(blob, now, true)
}

func (m *EntryMemory) RecordFail(transport string, now func() time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.readLocked(now)
	st.Failed = append(st.Failed, transport)
	return m.writeLocked(st)
}

// RecordWin keeps the legacy API and records only a transport winner.
func (m *EntryMemory) RecordWin(transport string, now func() time.Time) error {
	return m.RecordWinBridge(transport, "", now)
}

// RecordWinBridge records a winner only when the supervisor has actual
// attribution evidence. bridgeID is normally DedupKey(bridge).
func (m *EntryMemory) RecordWinBridge(transport, bridgeID string, now func() time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.readLocked(now)
	st.Winner = transport
	st.WinnerBridge = bridgeID
	return m.writeLocked(st)
}

func (m *EntryMemory) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := os.Remove(m.Path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (m *EntryMemory) readLocked(now func() time.Time) EntryMemoryState {
	blob, err := os.ReadFile(m.Path)
	if err != nil {
		return EntryMemoryState{At: now()}
	}
	st := m.parseLocked(blob, now, false)
	if st.At.IsZero() {
		st.At = now()
	}
	return st
}

func (m *EntryMemory) parseLocked(blob []byte, now func() time.Time, removeBad bool) EntryMemoryState {
	lines := strings.Split(strings.TrimSpace(string(blob)), "\n")
	if len(lines) < 1 || strings.TrimSpace(lines[0]) == "" {
		if removeBad {
			_ = os.Remove(m.Path)
		}
		return EntryMemoryState{}
	}
	ms, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	if err != nil || ms <= 0 {
		if removeBad {
			_ = os.Remove(m.Path)
		}
		return EntryMemoryState{}
	}
	at := time.UnixMilli(ms)
	if now().Sub(at) > EntryMemoryTTL {
		_ = os.Remove(m.Path)
		return EntryMemoryState{}
	}
	st := EntryMemoryState{At: at}
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "failed "):
			st.Failed = append(st.Failed, strings.TrimSpace(strings.TrimPrefix(l, "failed ")))
		case strings.HasPrefix(l, "winner_bridge "):
			st.WinnerBridge = strings.TrimSpace(strings.TrimPrefix(l, "winner_bridge "))
		case strings.HasPrefix(l, "winner "):
			st.Winner = strings.TrimSpace(strings.TrimPrefix(l, "winner "))
		}
	}
	return st
}

func (m *EntryMemory) writeLocked(st EntryMemoryState) error {
	if st.At.IsZero() {
		st.At = time.Now()
	}
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
	if st.WinnerBridge != "" {
		b.WriteString("winner_bridge ")
		b.WriteString(st.WinnerBridge)
		b.WriteByte('\n')
	}
	dir := filepath.Dir(m.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
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
