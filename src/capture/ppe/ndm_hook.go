package ppe

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultNDMHookPath = "/opt/etc/ndm/netfilter.d/94-b4-ppe-reconcile.sh"
	ndmHookMarker      = "# managed-by-b4-ppe-v1"
)

type NDMHookInstaller struct {
	Path string
}

func (i NDMHookInstaller) Install(platform PlatformMetadata) (bool, error) {
	if !platform.NDM {
		return false, nil
	}
	path := i.Path
	if path == "" {
		path = DefaultNDMHookPath
	}
	content := []byte(renderNDMHook())
	if current, err := os.ReadFile(path); err == nil {
		if bytes.Equal(current, content) {
			return false, nil
		}
		if !bytes.Contains(current, []byte(ndmHookMarker)) {
			return false, fmt.Errorf("refusing to replace unmanaged NDM hook %s", path)
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("read existing NDM hook: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("create NDM hook directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".b4-ppe-hook-*")
	if err != nil {
		return false, fmt.Errorf("create NDM hook temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return false, fmt.Errorf("write NDM hook: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		cleanup()
		return false, fmt.Errorf("chmod NDM hook: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return false, fmt.Errorf("sync NDM hook: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("close NDM hook: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("install NDM hook: %w", err)
	}
	return true, nil
}

func (i NDMHookInstaller) Remove() (bool, error) {
	path := i.Path
	if path == "" {
		path = DefaultNDMHookPath
	}
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Contains(content, []byte(ndmHookMarker)) {
		return false, fmt.Errorf("refusing to remove unmanaged NDM hook %s", path)
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	return true, nil
}

func renderNDMHook() string {
	return `#!/bin/sh
` + ndmHookMarker + `
export PATH=/opt/sbin:/opt/bin:/sbin:/usr/sbin:/bin:/usr/bin
case "$table" in
    mangle) ;;
    *) exit 0 ;;
esac
for pidfile in /var/run/b4.pid /run/b4.pid; do
    [ -r "$pidfile" ] || continue
    pid="$(cat "$pidfile" 2>/dev/null)"
    case "$pid" in
        ''|*[!0-9]*) continue ;;
    esac
    kill -USR1 "$pid" 2>/dev/null && exit 0
done
exit 0
`
}
