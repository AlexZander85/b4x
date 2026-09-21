package vless

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// Helper owns the external VLESS helper process (xray/sing-box): render its
// config, spawn it, wait for the SOCKS5 inbound to accept, supervise restarts
// and stop it. Design §7: b4x owns the lifecycle (Nova leaves this to Python).
type HelperSpec struct {
	// Kind selects the config dialect and the default argv.
	Kind HelperKind
	// BinPath is the helper binary ("" => the caller resolves it first).
	BinPath string
	// Args overrides the argv entirely (tests / custom wrappers).
	Args []string
	// ConfigPath is where the rendered config is written (0600).
	ConfigPath string
	// LogPath receives the helper stdout/stderr (0600).
	LogPath string
	// SocksAddr is the helper's local SOCKS5 inbound (host:port).
	SocksAddr string
	// ReadyTimeout bounds the readiness probe (0 => 20s).
	ReadyTimeout time.Duration
	// UDP enables the helper inbound's UDP ASSOCIATE (V3).
	UDP bool
	// Mixed asks for a single-port SOCKS+HTTP inbound (sing-box only).
	Mixed bool
}

// HelperStatus is the honest lifecycle snapshot for status/UI.
type HelperStatus struct {
	Configured bool   `json:"configured"`
	Running    bool   `json:"running"`
	Ready      bool   `json:"ready"`
	Restarts   int    `json:"restarts"`
	LastError  string `json:"last_error,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	LogPath    string `json:"log_path,omitempty"`
}

// Helper supervises one helper process.
type Helper struct {
	spec HelperSpec

	mu       sync.Mutex
	cmd      *exec.Cmd
	logFile  *os.File
	running  bool
	ready    bool
	restarts int
	lastErr  string
}

// NewHelper builds a helper supervisor (no process is started).
func NewHelper(spec HelperSpec) *Helper { return &Helper{spec: spec} }

// ConfigPath exposes the rendered config location.
func (h *Helper) ConfigPath() string { return h.spec.ConfigPath }

// RenderWrite renders the helper config for one node and writes it 0600.
func (h *Helper) RenderWrite(node Node) error {
	b, err := RenderWith(h.spec.Kind, node, RenderOptions{
		SocksAddr: h.spec.SocksAddr,
		UDP:       h.spec.UDP,
		Mixed:     h.spec.Mixed,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.spec.ConfigPath), 0o700); err != nil {
		return fmt.Errorf("vless: helper config dir: %w", err)
	}
	if err := os.WriteFile(h.spec.ConfigPath, b, 0o600); err != nil {
		return fmt.Errorf("vless: helper config write: %w", err)
	}
	return nil
}

// args is the helper argv: an explicit override wins, otherwise the dialect
// defaults (sing-box: `run -c <cfg>`, xray: `-config <cfg>`).
func (h *Helper) args() []string {
	if len(h.spec.Args) > 0 {
		return h.spec.Args
	}
	switch h.spec.Kind {
	case HelperSingbox:
		return []string{"run", "-c", h.spec.ConfigPath}
	default:
		return []string{"-config", h.spec.ConfigPath}
	}
}

// Start spawns the helper (idempotent while running).
func (h *Helper) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return nil
	}
	if h.spec.BinPath == "" {
		return errors.New("vless: helper binary path empty")
	}
	if err := os.MkdirAll(filepath.Dir(h.spec.LogPath), 0o700); err != nil {
		return fmt.Errorf("vless: helper log dir: %w", err)
	}
	lf, err := os.OpenFile(h.spec.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("vless: helper log: %w", err)
	}
	cmd := exec.CommandContext(ctx, h.spec.BinPath, h.args()...)
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		_ = lf.Close()
		h.lastErr = err.Error()
		return fmt.Errorf("vless: helper start: %w", err)
	}
	h.cmd = cmd
	h.logFile = lf
	h.running = true
	h.lastErr = ""
	return nil
}

// WaitReady polls the SOCKS5 inbound until it accepts or the timeout fires.
func (h *Helper) WaitReady(ctx context.Context) error {
	timeout := h.spec.ReadyTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := h.Probe(ctx); err == nil {
			h.mu.Lock()
			h.ready = true
			h.mu.Unlock()
			return nil
		}
		if time.Now().After(deadline) {
			h.mu.Lock()
			h.lastErr = "readiness timeout"
			h.mu.Unlock()
			return fmt.Errorf("vless: helper not ready on %s within %s", h.spec.SocksAddr, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Probe dials the SOCKS5 inbound.
func (h *Helper) Probe(ctx context.Context) error {
	if h.spec.SocksAddr == "" {
		return errors.New("vless: helper socks address empty")
	}
	d := &net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "tcp", h.spec.SocksAddr)
	if err != nil {
		return err
	}
	return c.Close()
}

// Stop kills the helper and waits for it (idempotent).
func (h *Helper) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopLocked()
}

func (h *Helper) stopLocked() {
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_, _ = h.cmd.Process.Wait()
	}
	h.cmd = nil
	h.running = false
	h.ready = false
	if h.logFile != nil {
		_ = h.logFile.Close()
		h.logFile = nil
	}
}

// Restart stops, re-spawns and waits ready (the supervisor's escalation).
func (h *Helper) Restart(ctx context.Context) error {
	h.Stop()
	h.mu.Lock()
	h.restarts++
	h.mu.Unlock()
	if err := h.Start(ctx); err != nil {
		return err
	}
	return h.WaitReady(ctx)
}

// Status snapshots the helper state.
func (h *Helper) Status() HelperStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return HelperStatus{
		Configured: true,
		Running:    h.running,
		Ready:      h.ready,
		Restarts:   h.restarts,
		LastError:  h.lastErr,
		ConfigPath: h.spec.ConfigPath,
		LogPath:    h.spec.LogPath,
	}
}
