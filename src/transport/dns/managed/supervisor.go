package managed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// BackendState is the supervisor-visible lifecycle state.
type BackendState string

const (
	StateStopped  BackendState = "stopped"
	StateStarting BackendState = "starting"
	StateReady    BackendState = "ready"
	StateDegraded BackendState = "degraded"
	StateFailed   BackendState = "failed"
	StateRetired  BackendState = "retired"
)

// QueryFunc is the functional readiness probe: it must complete a real DNS
// query through the managed listener. PID existence or a fixed sleep is
// never readiness (addendum §43).
type QueryFunc func(ctx context.Context, listenAddr string) error

// Supervisor owns one managed dnscrypt-proxy instance lifecycle.
type Supervisor struct {
	Manifest   BinaryManifest
	BinaryPath string
	WorkDir    string // owned temp dir for configs/pid; cleaned on retire
	Spec       InstanceSpec
	Readiness  QueryFunc

	MaxRestarts int
	BackoffBase time.Duration

	mu         sync.Mutex
	state      BackendState
	cmd        *exec.Cmd
	restarts   int
	configPath string
	lastErr    error
}

func NewSupervisor(manifest BinaryManifest, binaryPath, workDir string, spec InstanceSpec, readiness QueryFunc) *Supervisor {
	return &Supervisor{
		Manifest: manifest, BinaryPath: binaryPath, WorkDir: workDir, Spec: spec,
		Readiness: readiness, MaxRestarts: 3, BackoffBase: 500 * time.Millisecond,
	}
}

func (s *Supervisor) State() BackendState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Supervisor) setState(st BackendState) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
}

// Start verifies the binary, generates the isolated config, starts the
// process and waits for functional query readiness.
func (s *Supervisor) Start(ctx context.Context) error {
	if err := VerifyBinary(s.BinaryPath, s.Manifest); err != nil {
		s.setState(StateFailed)
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		return err
	}
	cfg, err := GenerateConfig(s.Spec)
	if err != nil {
		s.setState(StateFailed)
		return err
	}
	if err := ValidateKeys(cfg); err != nil {
		s.setState(StateFailed)
		return err
	}
	if err := os.MkdirAll(s.WorkDir, 0o700); err != nil {
		return err
	}
	s.configPath = filepath.Join(s.WorkDir, "dnscrypt-proxy.toml")
	if err := os.WriteFile(s.configPath, []byte(cfg), 0o600); err != nil {
		return err
	}
	s.setState(StateStarting)
	if err := s.spawn(); err != nil {
		s.setState(StateFailed)
		return err
	}
	if err := s.waitReady(ctx); err != nil {
		s.stopProcess()
		s.setState(StateFailed)
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		return err
	}
	s.setState(StateReady)
	return nil
}

func (s *Supervisor) spawn() error {
	cmd := exec.Command(s.BinaryPath, "-config", s.configPath)
	// Never inherit a controlling terminal; stdout/stderr are discarded by
	// default (raw query logs stay off, §50).
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("managed backend start: %w", err)
	}
	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()
	return nil
}

// waitReady polls functional readiness with backoff until ctx deadline.
func (s *Supervisor) waitReady(ctx context.Context) error {
	if s.Readiness == nil {
		return errors.New("readiness query function required")
	}
	deadline := time.Now().Add(15 * time.Second)
	attempt := 0
	for {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := s.Readiness(rctx, s.Spec.ListenAddr)
		cancel()
		if err == nil {
			return nil
		}
		attempt++
		if time.Now().After(deadline) {
			return fmt.Errorf("managed backend readiness timeout after %d attempts: %w", attempt, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
		}
	}
}

// Crash invalidates current health immediately (§52). The supervisor marks
// the instance failed; fast failover is a DNSPathManager decision.
func (s *Supervisor) NotifyCrash() {
	s.setState(StateFailed)
}

// Restart performs a bounded restart with backoff (§52).
func (s *Supervisor) Restart(ctx context.Context) error {
	s.mu.Lock()
	if s.restarts >= s.MaxRestarts {
		st := s.state
		s.mu.Unlock()
		return fmt.Errorf("managed backend restart budget exhausted (state %s)", st)
	}
	s.restarts++
	n := s.restarts
	s.mu.Unlock()
	s.stopProcess()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.BackoffBase * time.Duration(1<<(n-1))):
	}
	s.setState(StateStarting)
	if err := s.spawn(); err != nil {
		s.setState(StateFailed)
		return err
	}
	if err := s.waitReady(ctx); err != nil {
		s.stopProcess()
		s.setState(StateFailed)
		return err
	}
	s.setState(StateReady)
	return nil
}

func (s *Supervisor) stopProcess() {
	s.mu.Lock()
	cmd := s.cmd
	s.cmd = nil
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	// Kill only the exact process group we spawned; never name-match foreign
	// processes (§52).
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

// Retire stops the process and removes owned listeners, configs, pid files
// and temp state (§52). Foreign resources are never touched.
func (s *Supervisor) Retire(_ context.Context) error {
	s.stopProcess()
	s.setState(StateRetired)
	if s.WorkDir != "" {
		if err := os.RemoveAll(s.WorkDir); err != nil {
			return fmt.Errorf("managed backend cleanup incomplete: %w", err)
		}
	}
	return nil
}

// AllocateLoopbackPort reserves a free loopback port owned by B4X.
func AllocateLoopbackPort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}
