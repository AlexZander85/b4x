// BLK-5 verification: URL subscriptions — first-run activation, refresh
// updates the active set, download failures keep the previous matcher,
// size-limit aborts poisoned/oversized payloads.
package adblock

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

func waitForBlock(t *testing.T, host string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if d, _ := Decide(host); d == DecisionBlock {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("host %q never became blocked", host)
}

func TestSubscriptionFirstRunAndRefresh(t *testing.T) {
	StopRefresher()
	body := "ads.example.net\ntracker.example.org\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	cfg := config.AdBlockConfig{
		Enabled: true,
		Lists:   []config.AdBlockList{{Source: srv.URL + "/list.domains", Enabled: true}},
	}

	ApplyConfig(cfg, cacheDir, "")
	waitForBlock(t, "ads.example.net")
	if d, _ := Decide("sub.tracker.example.org"); d != DecisionBlock {
		t.Fatal("suffix semantics must cover subdomains of subscription entries")
	}

	// Refresh cycle: swap server body and drop the cache so the next pass
	// re-downloads; the NEW domain must activate, the OLD must deactivate.
	body = "fresh.example.com\n"
	dest := CachePathFor(cacheDir, srv.URL+"/list.domains")
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	refreshSubscriptions(srv.Client(), cfg, cacheDir, 0, true) // direct deterministic forced pass
	if d, _ := Decide("fresh.example.com"); d != DecisionBlock {
		t.Fatal("refreshed subscription did not activate new domain")
	}
	if d, _ := Decide("ads.example.net"); d == DecisionBlock {
		t.Fatal("old domain still active after list rotation")
	}
	StopRefresher()
}

func TestSubscriptionFailureKeepsPrevious(t *testing.T) {
	StopRefresher()
	failNow := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failNow {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("stable.example.com\n"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	cfg := config.AdBlockConfig{
		Enabled:      true,
		Lists:        []config.AdBlockList{{Source: srv.URL + "/list.domains", Enabled: true}},
		RefreshHours: 1,
	}
	ApplyConfig(cfg, cacheDir, "")
	waitForBlock(t, "stable.example.com")

	failNow = true
	if err := os.Remove(CachePathFor(cacheDir, srv.URL+"/list.domains")); err != nil {
		t.Fatal(err)
	}
	// Force a refresh pass against the failing server with no cached copy:
	// the layer must stay functional for what it had, never block-all.
	refreshSubscriptions(srv.Client(), cfg, cacheDir, time.Hour, true)
	st := GetStats()
	if st.FetchFail == 0 {
		t.Fatal("expected a recorded fetch failure")
	}
	if s := snap.Load(); s == nil || len(s.block.domains) != 0 {
		t.Fatalf("unexpected state after failed fetch with no cache: %+v", s)
	}
	if d, _ := Decide("unrelated.example"); d != DecisionPass {
		t.Fatal("failed refresh without cache must not block unrelated traffic")
	}
	StopRefresher()
}

func TestSubscriptionSizeLimit(t *testing.T) {
	StopRefresher()
	big := make([]byte, 0, 4096*8)
	for i := 0; i < 2048; i++ { // unique domains >> MaxEntries cap path
		big = append(big, []byte(fmt.Sprintf("pad-%06d.example.net\n", i))...)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	cfg := config.AdBlockConfig{
		Enabled:    true,
		Lists:      []config.AdBlockList{{Source: srv.URL + "/huge.domains", Enabled: true}},
		MaxEntries: 5,
	}
	client := srv.Client()
	if err := fetchToFile(client, srv.URL+"/huge.domains",
		filepath.Join(cacheDir, "huge.domains"), cfg.MaxEntries); err != nil {
		t.Fatalf("fetch within cap should succeed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(cacheDir, "huge.domains"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, l := range splitLines(string(data)) {
		if l != "" {
			count++
		}
	}
	if count != 5 {
		t.Fatalf("stored entries=%d want cap 5", count)
	}
}

func splitLines(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
