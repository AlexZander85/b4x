package mtproto

import (
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

// b4x-0z7: the transparent bridge's generic fail-open must use the shared
// CF-proxy pool when the owner's private worker domain is unset, otherwise
// HTTPS/WSS to a Telegram DC IP (web.telegram.org) dead-ends on a direct dial.

func TestCFProxyFailOpenHosts_DCPrefix(t *testing.T) {
	cases := []struct {
		dc         int
		wantPrefix string
	}{
		{2, "kws2."},
		{-2, "kws2."},
		{4, "kws4."},
		{-4, "kws4."},
		{0, "kws2."}, // non-DC destination -> kws2 fallback
		{9, "kws2."}, // out-of-range -> kws2 fallback
	}
	for _, tc := range cases {
		hosts := cfProxyFailOpenHosts(tc.dc)
		if len(hosts) == 0 {
			t.Fatalf("dc=%d: pool must not be empty", tc.dc)
		}
		for _, h := range hosts {
			if !strings.HasPrefix(h, tc.wantPrefix) {
				t.Errorf("dc=%d: host %q lacks prefix %q", tc.dc, h, tc.wantPrefix)
			}
			if strings.HasSuffix(h, ".") || !strings.Contains(h, ".") {
				t.Errorf("dc=%d: host %q malformed", tc.dc, h)
			}
		}
	}
}

func TestFailOpenWorkerHosts_PrivateWinsThenCFPool(t *testing.T) {
	priv := &config.MTProtoConfig{CFWorkerDomain: "my-worker.user.workers.dev, other.workers.dev"}
	got := failOpenWorkerHosts(priv, 2)
	if len(got) != 2 || got[0] != "my-worker.user.workers.dev" || got[1] != "other.workers.dev" {
		t.Fatalf("configured private workers must be used as-is, got %v", got)
	}

	empty := &config.MTProtoConfig{}
	fb := failOpenWorkerHosts(empty, 2)
	if len(fb) == 0 {
		t.Fatal("empty cf_worker_domain must fall back to the CF-proxy pool")
	}
	for _, h := range fb {
		if !strings.HasPrefix(h, "kws2.") {
			t.Errorf("fallback host %q lacks kws2. prefix", h)
		}
	}
}
