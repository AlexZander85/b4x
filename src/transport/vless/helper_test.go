package vless

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHelperRenderWrite(t *testing.T) {
	dir := t.TempDir()
	h := NewHelper(HelperSpec{
		Kind:       HelperXray,
		ConfigPath: filepath.Join(dir, "helper.json"),
		LogPath:    filepath.Join(dir, "helper.log"),
		SocksAddr:  "127.0.0.1:1081",
	})
	n := mustNode(t, realityURI)
	if err := h.RenderWrite(n); err != nil {
		t.Fatalf("render: %v", err)
	}
	fi, err := os.Stat(h.ConfigPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o want 600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(h.ConfigPath())
	if !strings.Contains(string(b), `"vless"`) || !strings.Contains(string(b), `"socks"`) {
		t.Fatalf("config missing vless/socks: %s", b)
	}
}

func TestHelperProbeAndWaitReady(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := NewHelper(HelperSpec{SocksAddr: ln.Addr().String(), ReadyTimeout: time.Second})
	ctx := context.Background()
	if err := h.Probe(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := h.WaitReady(ctx); err != nil {
		t.Fatalf("wait ready: %v", err)
	}
	if !h.Status().Ready {
		t.Fatal("status should be ready")
	}
}

func TestHelperWaitReadyTimeout(t *testing.T) {
	// A port with nobody listening: acquire one then close the listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	h := NewHelper(HelperSpec{SocksAddr: addr, ReadyTimeout: 150 * time.Millisecond})
	if err := h.WaitReady(context.Background()); err == nil {
		t.Fatal("wait ready must time out with no listener")
	}
}

func TestHelperStartStop(t *testing.T) {
	dir := t.TempDir()
	h := NewHelper(HelperSpec{
		Kind:       HelperXray,
		BinPath:    "/bin/sh",
		Args:       []string{"-c", "sleep 30"},
		ConfigPath: filepath.Join(dir, "helper.json"),
		LogPath:    filepath.Join(dir, "helper.log"),
		SocksAddr:  "127.0.0.1:1",
	})
	if err := h.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !h.Status().Running {
		t.Fatal("helper should be running")
	}
	h.Stop()
	if h.Status().Running {
		t.Fatal("helper should be stopped")
	}
}
