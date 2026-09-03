package runtimecontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

type LastGoodStore interface {
	Prepare(LastGoodRecord) error
	Commit(LastGoodRecord) error
	Abort() error
	Load() (*LastGoodRecord, error)
}

type MemoryLastGoodStore struct {
	mu      sync.Mutex
	pending *LastGoodRecord
	good    *LastGoodRecord
}

func (s *MemoryLastGoodStore) Prepare(record LastGoodRecord) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := record.clone()
	s.pending = &r
	return nil
}
func (s *MemoryLastGoodStore) Commit(record LastGoodRecord) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := record.clone()
	s.good = &r
	s.pending = nil
	return nil
}
func (s *MemoryLastGoodStore) Abort() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = nil
	return nil
}
func (s *MemoryLastGoodStore) Load() (*LastGoodRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.good == nil {
		return nil, nil
	}
	r := s.good.clone()
	return &r, nil
}

type diskLastGood struct {
	SchemaVersion int            `json:"schema_version"`
	State         string         `json:"state"`
	Record        LastGoodRecord `json:"record"`
}

// FileLastGoodStore uses a pending sidecar followed by an atomic committed
// file. A crash before Commit leaves the previous committed record intact.
type FileLastGoodStore struct {
	Path string
	mu   sync.Mutex
}

func (s *FileLastGoodStore) Prepare(record LastGoodRecord) error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return errors.New("last-good path is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeAtomic(s.Path+".pending", diskLastGood{SchemaVersion: LastGoodSchemaVersion, State: "pending", Record: record.clone()})
}
func (s *FileLastGoodStore) Commit(record LastGoodRecord) error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return errors.New("last-good path is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeAtomic(s.Path, diskLastGood{SchemaVersion: LastGoodSchemaVersion, State: "committed", Record: record.clone()}); err != nil {
		return err
	}
	_ = os.Remove(s.Path + ".pending")
	return nil
}
func (s *FileLastGoodStore) Abort() error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.Path + ".pending"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (s *FileLastGoodStore) Load() (*LastGoodRecord, error) {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return nil, errors.New("last-good path is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var disk diskLastGood
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, fmt.Errorf("decode last-good: %w", err)
	}
	if disk.SchemaVersion != LastGoodSchemaVersion || disk.State != "committed" || disk.Record.SchemaVersion != LastGoodSchemaVersion {
		return nil, fmt.Errorf("unsupported last-good record")
	}
	r := disk.Record.clone()
	return &r, nil
}
func (s *FileLastGoodStore) writeAtomic(path string, value diskLastGood) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".b4-last-good-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	encErr := json.NewEncoder(tmp).Encode(value)
	if encErr == nil {
		encErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if encErr != nil {
		cleanup()
		return encErr
	}
	if closeErr != nil {
		cleanup()
		return closeErr
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

type CooldownKey struct {
	SetID               string `json:"set_id"`
	ClientGroup         string `json:"client_group"`
	Protocol            string `json:"protocol"`
	CandidateGeneration string `json:"candidate_generation"`
}

type Cooldown struct {
	mu       sync.Mutex
	clock    clock.Clock
	duration time.Duration
	max      int
	entries  map[CooldownKey]time.Time
}

func NewCooldown(duration time.Duration, clk clock.Clock, maxEntries int) *Cooldown {
	if duration <= 0 {
		duration = DefaultCooldown
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	if maxEntries <= 0 {
		maxEntries = 256
	}
	return &Cooldown{clock: clk, duration: duration, max: maxEntries, entries: make(map[CooldownKey]time.Time)}
}

func (c *Cooldown) Check(key CooldownKey) error {
	if c == nil {
		return nil
	}
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for candidate, until := range c.entries {
		if !now.Before(until) {
			delete(c.entries, candidate)
		}
	}
	if until, ok := c.entries[key]; ok && now.Before(until) {
		return fmt.Errorf("%w until %s", ErrCooldown, until.UTC().Format(time.RFC3339Nano))
	}
	return nil
}
func (c *Cooldown) RecordFailure(key CooldownKey) {
	if c == nil {
		return
	}
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		var oldest CooldownKey
		var oldestAt time.Time
		for candidate, at := range c.entries {
			if oldestAt.IsZero() || at.Before(oldestAt) {
				oldest, oldestAt = candidate, at
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[key] = now.Add(c.duration)
}
func (c *Cooldown) RecordSuccess(key CooldownKey) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}
func (c *Cooldown) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
