package fieldtest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsVirtualIfaceName(t *testing.T) {
	virtual := []string{"vEthernet (WSL (Hyper-V firewall))", "vEthernet (Default Switch)", "DockerNAT", "tailscale0", "vSwitch"}
	for _, name := range virtual {
		if !isVirtualIfaceName(name) {
			t.Errorf("expected %q to be virtual", name)
		}
	}
	real := []string{"Ethernet", "Wi-Fi", "eth0", "enp0s3", "en0"}
	for _, name := range real {
		if isVirtualIfaceName(name) {
			t.Errorf("expected %q to be real", name)
		}
	}
}

func TestDiscoverEnvFailClosedWithoutRouterOrADB(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Setenv("B4_RESULTS_DIR", dir)
	t.Setenv("B4_WINDOWS_LAN_IP", "")
	t.Setenv("B4_ROUTER_HOST", "")
	p := DiscoverEnv(ctx, "", dir, "")
	if p.Ready {
		t.Fatal("preflight must not be ready without router HTTP and ADB")
	}
	found := false
	for _, b := range p.Blocking {
		if strings.Contains(b, "android ADB") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected android ADB block, got %v", p.Blocking)
	}
	if !p.ResultsDirWritable {
		t.Fatal("results dir should be writable")
	}
}

func TestDiscoverEnvResultsDirCreation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "field-runs")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Setenv("B4_ROUTER_HOST", "")
	p := DiscoverEnv(ctx, "", dir, "")
	if !p.ResultsDirWritable {
		t.Fatalf("expected dir %s to be created and writable, blocking=%v", dir, p.Blocking)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir not created: %v", err)
	}
}
