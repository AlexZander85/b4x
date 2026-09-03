// Package fxvpn implements the Firefox VPN reserve transport (E-FXVPN,
// design .ag/research/fxvpn-reserve-design.md Parts I+II). It is a peer of
// transport/warp and transport/wg: same storage discipline (atomic 0600
// secret files with *.corrupt quarantine), same fail-closed instincts, zero
// new external dependencies.
//
// This file holds the shared on-disk primitives: every fxvpn store
// (accounts.json, TOFU pin store, server-list cache) persists through
// saveAtomic and quarantines through quarantinePath. The pattern mirrors
// transport/warp IdentityStore: temp file in the same directory, 0600,
// fsync, rename over the target; a corrupt file is renamed *.corrupt so the
// evidence survives for forensics and callers see a clean absent state.
package fxvpn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// saveAtomic writes blob to path transactionally: temp file in the same
// directory, chmod 0600 (best-effort on non-POSIX platforms; production
// target is Linux where it is mandatory for secret files), fsync, rename.
// A failure anywhere leaves the previous generation untouched.
func saveAtomic(path string, blob []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
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
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// writeSecretFile performs write+chmod+sync+close on an open temp file.
func writeSecretFile(f *os.File, blob []byte) error {
	if _, err := f.Write(blob); err != nil {
		return err
	}
	_ = f.Chmod(0o600)
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fxvpn: fsync %s: %w", f.Name(), err)
	}
	return f.Close()
}

// quarantinePath renames path to path+".corrupt" (replacing any earlier
// quarantine). Evidence survives; the store becomes absent.
func quarantinePath(path string) error {
	return os.Rename(path, path+".corrupt")
}

// readStoreFile reads a store file applying the common discipline:
// missing -> ErrStoreAbsent (clean first-provision path); anything else that
// prevents parsing is the caller's business (it quarantines via quarantinePath).
func readStoreFile(path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrStoreAbsent
		}
		return nil, err
	}
	return blob, nil
}
