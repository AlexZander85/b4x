package tor

// Tor process supervision (patch-plan §7.2, design §7.2): spawn the
// external C-tor from Entware (or the owner's path) with argv-carried
// paths, an empty DefaultsTorrcFile and the owning-controller pid in the
// rendered torrc (b4 death = tor death, the reverse never holds).
//
// Identification discipline (the Nova lesson): a tor pid is only OURS when
// BOTH the pid matches AND /proc/<pid>/exe equals the expected binary —
// killing by process NAME is forbidden (the router may legitimately run
// an Entware tor service of its own). Stop is the graded ladder:
// SIGNAL SHUTDOWN → 3s → SIGTERM → 3s → SIGKILL.

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

// Process supervision constants (design §7.2).
const (
	ProcessShutdownGrace = 3 * time.Second
	ProcessTermGrace     = 3 * time.Second
	// OOM-suspect window: three immediate deaths in a row.
	ProcessOOMDeaths = 3
)

// ErrProcessNotOurs refuses an operation on a pid that fails the pid+exe
// pair check.
var ErrProcessNotOurs = errors.New("tor process identification failed (pid+exe mismatch)")

// ProcessDeath carries the wait result of a dead tor.
type ProcessDeath struct {
	Err  error
	Exit int
}

// ProcessHandle is one supervised tor process.
type ProcessHandle struct {
	binaryPath string
	dataPath   string
	pidFile    string
	cmd        *exec.Cmd

	mu        sync.Mutex
	death     chan ProcessDeath
	deathOnce sync.Once
}

// SpawnTor starts the tor binary with the rendered torrc (paths on argv:
// -f torrc --DefaultsTorrcFile <empty> --DataDirectory <data>). The
// environment is minimal (PATH only — tor needs nothing else).
func SpawnTor(ctx context.Context, binaryPath, torrcPath, dataPath string) (*ProcessHandle, error) {
	if _, err := os.Stat(binaryPath); err != nil {
		return nil, fmt.Errorf("tor binary %q: %w", binaryPath, err)
	}
	if err := os.MkdirAll(filepath.Join(dataPath, "data"), 0o700); err != nil {
		return nil, fmt.Errorf("tor data dir: %w", err)
	}
	torrcFile := torrcPath
	if err := os.Chmod(torrcFile, 0o600); err != nil {
		return nil, fmt.Errorf("torrc chmod: %w", err)
	}

	// The cookie file is written by tor at start under data/; nothing to
	// pre-create. The pid file records OUR identification pair.
	pidFile := filepath.Join(dataPath, "tor.pid")
	_ = os.Remove(pidFile)

	cmd := exec.Command(binaryPath,
		"-f", torrcFile,
		"--DefaultsTorrcFile", filepath.Join(dataPath, "torrc-defaults"),
		"--DataDirectory", filepath.Join(dataPath, "data"),
		"--PidFile", pidFile,
	)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Stdout = torLogWriter{tag: "tor"}
	cmd.Stderr = torLogWriter{tag: "tor-err"}

	h := &ProcessHandle{
		binaryPath: binaryPath,
		dataPath:   dataPath,
		pidFile:    pidFile,
		cmd:        cmd,
		death:      make(chan ProcessDeath, 1),
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tor spawn: %w", err)
	}
	// empty defaults file (the "no foreign defaults" contract)
	if err := os.WriteFile(filepath.Join(dataPath, "torrc-defaults"), nil, 0o600); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("torrc-defaults: %w", err)
	}
	// record the identification pair
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n%s\n", cmd.Process.Pid, binaryPath)), 0o600); err != nil {
		log.Tracef("[tor] pid file write: %v", err)
	}
	go h.wait()
	return h, nil
}

// wait reaps the process exactly once and broadcasts the death.
func (h *ProcessHandle) wait() {
	err := h.cmd.Wait()
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitCode()
		}
	}
	h.deathOnce.Do(func() {
		h.death <- ProcessDeath{Err: err, Exit: exit}
	})
}

// PID returns the spawned process id (0 after death).
func (h *ProcessHandle) PID() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd.Process == nil {
		return 0
	}
	return h.cmd.Process.Pid
}

// Death returns the death notification channel.
func (h *ProcessHandle) Death() <-chan ProcessDeath { return h.death }

// OwnsPID verifies the pid+exe pair against the expected binary — the
// ONLY sanctioned way to attribute a tor process to us before a kill.
func OwnsPID(pid int, expectedBinary string) bool {
	if pid <= 0 || expectedBinary == "" {
		return false
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	// the kernel suffixes deleted binaries with " (deleted)"
	if strings.HasSuffix(exe, " (deleted)") {
		exe = strings.TrimSuffix(exe, " (deleted)")
	}
	return exe == expectedBinary
}

// Stop runs the graded shutdown ladder; the ctx bounds the total wait.
func (h *ProcessHandle) Stop(ctx context.Context, ctl ControlClient) {
	h.mu.Lock()
	proc := h.cmd.Process
	h.mu.Unlock()
	if proc == nil {
		return
	}

	// grade 1: SIGNAL SHUTDOWN (clean drain)
	if ctl != nil {
		if err := ctl.Signal("SHUTDOWN"); err != nil {
			log.Tracef("[tor] SHUTDOWN signal: %v", err)
		}
		if h.awaitDeath(ctx, ProcessShutdownGrace) {
			return
		}
	}
	// grade 2: SIGTERM
	_ = proc.Signal(syscall.SIGTERM)
	if h.awaitDeath(ctx, ProcessTermGrace) {
		return
	}
	// grade 3: SIGKILL
	_ = proc.Kill()
	h.awaitDeath(ctx, ProcessShutdownGrace)
	_ = os.Remove(h.pidFile)
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

// ReadPidFile decodes the recorded identification pair.
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
	exe = ""
	if len(lines) > 1 {
		exe = strings.TrimSpace(lines[1])
	}
	return pid, exe, nil
}

// DetectTorVersion shells `tor --version` (honest binary-missing state is
// the CALLER's concern; a version probe failure is not fatal).
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

// torLogWriter funnels tor's own stdout/stderr into our trace log.
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
