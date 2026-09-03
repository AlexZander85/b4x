package ppe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNDMHookInstallIsAtomicAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netfilter.d", "94-b4-ppe-reconcile.sh")
	installer := NDMHookInstaller{Path: path}
	changed, err := installer.Install(PlatformMetadata{NDM: true})
	if err != nil || !changed {
		t.Fatalf("install changed=%v err=%v", changed, err)
	}
	changed, err = installer.Install(PlatformMetadata{NDM: true})
	if err != nil || changed {
		t.Fatalf("idempotent install changed=%v err=%v", changed, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, fragment := range []string{ndmHookMarker, `case "$table"`, "mangle", "kill -USR1", "/var/run/b4.pid", "/run/b4.pid"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("hook missing %q:\n%s", fragment, text)
		}
	}
	if shell, err := exec.LookPath("sh"); err == nil {
		if out, err := exec.Command(shell, "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("shell syntax: %v: %s", err, out)
		}
	}
}

func TestNDMHookUnsupportedPlatformNoMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook.sh")
	changed, err := (NDMHookInstaller{Path: path}).Install(PlatformMetadata{NDM: false})
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unsupported platform created hook: %v", err)
	}
}

func TestNDMHookRemoveOnlyOwnedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	installer := NDMHookInstaller{Path: path}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n# foreign\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Remove(); err == nil {
		t.Fatal("unmanaged hook was removed")
	}
	if _, err := installer.Install(PlatformMetadata{NDM: true}); err == nil {
		t.Fatal("unmanaged hook was overwritten")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("unmanaged hook disappeared")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Install(PlatformMetadata{NDM: true}); err != nil {
		t.Fatal(err)
	}
	removed, err := installer.Remove()
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("owned hook remains: %v", err)
	}
}
