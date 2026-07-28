package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreparedConfigSaveDoesNotPublishBeforeCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b4.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig()
	prepared, err := cfg.PrepareSave(path)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Abort()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != "old" {
		t.Fatalf("prepare published data early: %q", before)
	}
	if err := prepared.Commit(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == "old" || len(after) == 0 {
		t.Fatalf("commit did not publish config: %q", after)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions=%o, want 600", info.Mode().Perm())
	}
}

func TestPreparedConfigSaveAbortKeepsOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b4.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig()
	prepared, err := cfg.PrepareSave(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Abort(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("abort changed published config: %q", data)
	}
}
