package providers

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemForwardSharesResolverIdentityWithExplicitPath(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver 8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	system := NewSystemForwardProvider(resolv, nil, 0)
	udp := NewUDPProvider(netip.MustParseAddr("8.8.8.8"), 53, 0, "test")
	tcp := NewTCPProvider(netip.MustParseAddr("8.8.8.8"), 53, 0, "test")
	if system.ID().ResolverID != udp.ID().ResolverID || system.ID().ResolverID != tcp.ID().ResolverID {
		t.Fatalf("same physical resolver must share resolver identity: system=%q udp=%q tcp=%q", system.ID().ResolverID, udp.ID().ResolverID, tcp.ID().ResolverID)
	}
	if system.ID().Family == udp.ID().Family {
		t.Fatal("system-forward must remain a distinct path family")
	}
}
