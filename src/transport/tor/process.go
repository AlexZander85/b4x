package tor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/log"
)

const (
	ProcessShutdownGrace = 3 * time.Second
	ProcessTermGrace     = 3 * time.Second
	ProcessOOMDeaths     = 3
)

var ErrProcessNotOurs = errors.New("tor process identification failed (pid+exe mismatch)")

type ProcessDeath struct {
	Err  error
	Exit int
}

type ProcessHandle struct {
	binaryPath string
	dataPath   string
	pidFile    string
	nativePID  string
	cmd        *exec.Cmd

	mu        sync.Mutex
	exited    bool
	death     chan ProcessDeath
	deathOnce sync.Once
}

func SpawnTor(ctx context.Context, binaryPath, torrcPath, dataPath string) (*ProcessHandle, error) {
	if _, err := os.Stat(binaryPath); err != nil {
		return nil, fmt.Errorf("tor binary %q: %w", binaryPath, err)
	}
	if err := os.MkdirAll(filepath.Join(dataPath, "data"), 0o700); err != nil {
		return nil, fmt.Errorf("tor data dir: %w", err)
	}
	if err := os.Chmod(torrcPath, 0o600); err != nil {
		return nil, fmt.Errorf("torrc chmod: %w", err)
	}
	defaultsFile := filepath.Join(dataPath, "torrc-defaults")
	if err := os.WriteFile(defaultsFile, nil, 0o600); err != nil {
		return nil, fmt.Errorf("torrc-defaults: %w", err)
	}

	pidFile := filepath.Join(dataPath, "tor.pid")
	nativePID := filepath.Join(dataPath, "tor-native.pid")
	_ = os.Remove(pidFile)
	_ = os.Remove(nativePID)

	expectedExe := binaryPath
	if resolved, err := filepath.EvalSymlinks(binaryPath); err == nil {
		expectedExe = resolved
	}
	if abs, err := filepath.Abs(expectedExe); err == nil {
		expectedExe = abs
	}

	cmd := exec.Command(binaryPath,
		"-f", torrcPath,
		"--DefaultsTorrcFile", defaultsFile,
		"--DataDirectory", filepath.Join(dataPath, "data"),
		"--PidFile", nativePID,
	)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Stdout = torLogWriter{tag: "tor"}
	cmd.Stderr = torLogWriter{tag: "tor-err"}

	h := &ProcessHandle{
		binaryPath: expectedExe,
		dataPath:   dataPath,
		pidFile:    pidFile,
		nativePID:  nativePID,
		cmd:        cmd,
		death:      make(chan ProcessDeath, 1),
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tor spawn: %w", err)
	}
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n%s\n", cmd.Process.Pid, expectedExe)), 0o600); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, fmt.Errorf("tor ownership pid file: %w", err)
	}
	go h.wait()
	return h, nil
}

func (h *ProcessHandle) wait() {
	err := h.cmd.Wait()
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitCode()
		}
	}
	h.mu.Lock()
	h.exited = true
	h.mu.Unlock()
	h.deathOnce.Do(func() {
		h.death <- ProcessDeath{Err: err, Exit: exit}
	})
}

func (h *ProcessHandle) PID() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.exited || h.cmd == nil || h.cmd.Process == nil {
		return 0
	}
	return h.cmd.Process.Pid
}

// Alive lets the service prove that a guarded Stop actually retired the
// process before it discards the handle and permits a replacement spawn.
func (h *ProcessHandle) Alive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.exited && h.cmd != nil && h.cmd.Process != nil
}

func (h *ProcessHandle) Death() <-chan ProcessDeath { return h.death }

func OwnsPID(pid int, expectedBinary string) bool {
	if pid <= 0 || expectedBinary == "" {
		return false
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	if strings.HasSuffix(exe, " (deleted)") {
		exe = strings.TrimSuffix(exe, " (deleted)")
	}
	expected := expectedBinary
	if resolved, err := filepath.EvalSymlinks(expectedBinary); err == nil {
		expected = resolved
	}
	if abs, err := filepath.Abs(expected); err == nil {
		expected = abs
	}
	return exe == expected
}

func (h *ProcessHandle) Stop(ctx context.Context, ctl ControlClient) {
	h.mu.Lock()
	if h.exited || h.cmd == nil || h.cmd.Process == nil {
		h.mu.Unlock()
		return
	}
	proc := h.cmd.Process
	pid := proc.Pid
	h.mu.Unlock()
	defer func() {
		_ = os.Remove(h.pidFile)
		_ = os.Remove(h.nativePID)
	}()

	if ctl != nil {
		if err := ctl.Signal("SHUTDOWN"); err != nil {
			log.Tracef("[tor] SHUTDOWN signal: %v", err)
		}
		if h.awaitDeath(ctx, ProcessShutdownGrace) {
			return
		}
	}
	if !OwnsPID(pid, h.binaryPath) {
		log.Tracef("[tor] refusing SIGTERM for pid=%d: %v", pid, ErrProcessNotOurs)
		return
	}
	_ = proc.Signal(syscall.SIGTERM)
	if h.awaitDeath(ctx, ProcessTermGrace) {
		return
	}
	if !OwnsPID(pid, h.binaryPath) {
		log.Tracef("[tor] refusing SIGKILL for pid=%d: %v", pid, ErrProcessNotOurs)
		return
	}
	_ = proc.Kill()
	_ = h.awaitDeath(ctx, ProcessShutdownGrace)
}

func (h *ProcessHandle) awaitDeath(parent context.Context, grace time.Duration) bool {
	gctx, cancel := context.WithTimeout(parent, grace)
	defer cancel()
	select {
	case <-h.death:
		return true
	case <-gctx.Done():
		return false
	}
}

func ReadPidFile(path string) (pid int, exe string, err error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	lines := strings.Split(strings.TrimSpace(string(blob)), "\n")
	if len(lines) < 1 {
		return 0, "", fmt.Errorf("pid file empty")
	}
	pid, err = strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		return 0, "", fmt.Errorf("pid file pid: %w", err)
	}
	if len(lines) > 1 {
		exe = strings.TrimSpace(lines[1])
	}
	return pid, exe, nil
}

func DetectTorVersion(ctx context.Context, binaryPath string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, binaryPath, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("tor --version: %w", err)
	}
	first := strings.TrimSpace(string(out))
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	return first, nil
}

type torLogWriter struct{ tag string }

func (w torLogWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line == "" {
			continue
		}
		log.Tracef("[tor/%s] %s", w.tag, line)
	}
	return len(p), nil
}
