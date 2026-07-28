package config

import (
	"os"
	"path/filepath"

	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/packetmark"
)

type PreparedConfigSave struct {
	path      string
	tmpPath   string
	committed bool
}

// PrepareSave writes and fsyncs a complete configuration snapshot beside the
// destination without publishing it. Commit performs the single atomic rename;
// Abort removes the prepared snapshot. This is used by transactional runtime
// promotion so disk and packet state can be rolled back together.
func (c *Config) PrepareSave(path string) (*PreparedConfigSave, error) {
	if path == "" {
		return &PreparedConfigSave{}, nil
	}

	c.Version = CurrentConfigVersion
	data, err := MarshalSparse(stripCLIOverrides(c))
	if err != nil {
		return nil, log.Errorf("failed to marshal config: %v", err)
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, log.Errorf("failed to create config directory: %v", err)
	}
	file, err := os.CreateTemp(dir, ".b4-config-*.tmp")
	if err != nil {
		return nil, log.Errorf("failed to create temporary config file: %v", err)
	}
	tmpPath := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(tmpPath)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanup()
		return nil, log.Errorf("failed to set config file permissions: %v", err)
	}
	if _, err = file.Write(data); err != nil {
		cleanup()
		return nil, log.Errorf("failed to write config file: %v", err)
	}
	if err = file.Sync(); err != nil {
		cleanup()
		return nil, log.Errorf("failed to sync config file: %v", err)
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, log.Errorf("failed to close config file: %v", err)
	}
	return &PreparedConfigSave{path: path, tmpPath: tmpPath}, nil
}

func (s *PreparedConfigSave) Commit() error {
	if s == nil || s.path == "" {
		return nil
	}
	if s.committed {
		return nil
	}
	if s.tmpPath == "" {
		return log.Errorf("prepared config snapshot is missing")
	}
	if err := os.Rename(s.tmpPath, s.path); err != nil {
		return log.Errorf("failed to replace config file atomically: %v", err)
	}
	s.committed = true
	s.tmpPath = ""
	dirPath := filepath.Dir(s.path)
	if dirPath == "" {
		dirPath = "."
	}
	if dir, err := os.Open(dirPath); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (s *PreparedConfigSave) Abort() error {
	if s == nil || s.committed || s.tmpPath == "" {
		return nil
	}
	err := os.Remove(s.tmpPath)
	s.tmpPath = ""
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Canary marks use a versioned reserved mask instead of arithmetic based on
// Queue.Mark. This prevents a candidate flow from matching the production
// injected-packet mask when the legacy mark is a single bit such as 0x8000.
func (c *Config) CanaryFlowMark() uint     { return uint(packetmark.CanarySelectedBit) }
func (c *Config) CanaryDirectMark() uint   { return uint(packetmark.CanaryDirectBit) }
func (c *Config) CanaryInjectedMark() uint { return uint(packetmark.CanaryInjectedBit) }
