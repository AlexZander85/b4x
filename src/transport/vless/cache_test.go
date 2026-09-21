package vless

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRefreshWithStateConditional(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(realityURI + "\n"))
	var mu sync.Mutex
	fetches, lastINM := 0, ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetches++
		inm := r.Header.Get("If-None-Match")
		if inm != "" {
			lastINM = inm
		}
		mu.Unlock()
		if inm == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	rep1 := RefreshWithState(context.Background(), srv.Client(), []string{srv.URL}, nil, 0)
	if len(rep1.Nodes) != 1 {
		t.Fatalf("first refresh nodes=%d want 1", len(rep1.Nodes))
	}
	key := sourceKey(srv.URL)
	if rep1.BySource[key].ETag != `"v1"` {
		t.Fatalf("etag not stored: %+v", rep1.BySource[key])
	}

	rep2 := RefreshWithState(context.Background(), srv.Client(), []string{srv.URL}, rep1.BySource, 0)
	if len(rep2.Nodes) != 1 {
		t.Fatalf("304 must retain last-good nodes, got %d", len(rep2.Nodes))
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches != 2 || lastINM != `"v1"` {
		t.Fatalf("conditional GET not sent: fetches=%d If-None-Match=%q", fetches, lastINM)
	}
}

func TestRefreshWithStateKeepsLastGoodOnFailure(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(wsURI + "\n"))
	fail := false
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		f := fail
		mu.Unlock()
		if f {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	rep1 := RefreshWithState(context.Background(), srv.Client(), []string{srv.URL}, nil, 0)
	if len(rep1.Nodes) != 1 {
		t.Fatalf("first refresh nodes=%d want 1", len(rep1.Nodes))
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	rep2 := RefreshWithState(context.Background(), srv.Client(), []string{srv.URL}, rep1.BySource, 0)
	if len(rep2.Nodes) != 1 {
		t.Fatalf("failed source must keep last-good nodes, got %d", len(rep2.Nodes))
	}
	if len(rep2.Failed) != 1 {
		t.Fatalf("failure not recorded: %v", rep2.Failed)
	}
}

func TestNodeCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nodes.json")
	c := &NodeCache{
		Nodes: []Node{{UUID: "u", Host: "h.example.org", Port: 443,
			Security: SecurityTLS, SNI: "www.microsoft.com", Transport: TransportTCP}},
		Sources:   []string{"https://agg.example.org/<redacted>"},
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := c.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %o want 600", fi.Mode().Perm())
	}
	got, err := LoadNodeCache(path)
	if err != nil || got == nil || len(got.Nodes) != 1 {
		t.Fatalf("load: %v %+v", err, got)
	}
	if got.Nodes[0].Host != "h.example.org" {
		t.Fatalf("round-trip node mismatch: %+v", got.Nodes[0])
	}
	// Missing file is the honest empty state, not an error.
	if c2, err := LoadNodeCache(filepath.Join(dir, "absent.json")); err != nil || c2 != nil {
		t.Fatalf("absent cache = %v, %v; want nil, nil", c2, err)
	}
	// Corrupt file is an error the caller tolerates.
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeCache(filepath.Join(dir, "bad.json")); err == nil {
		t.Fatal("corrupt cache must error")
	}
}

func TestRefreshMergesAndDedups(t *testing.T) {
	body := realityURI + "\n" + wsURI + "\n" + realityURI + "\n"
	raw := base64.StdEncoding.EncodeToString([]byte(body))
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, raw)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer bad.Close()

	rep := Refresh(context.Background(), http.DefaultClient, []string{good.URL, bad.URL}, 0)
	if len(rep.Nodes) != 2 {
		t.Fatalf("nodes=%d want 2 (stats=%+v failed=%v)", len(rep.Nodes), rep.Stats, rep.Failed)
	}
	if len(rep.Sources) != 1 {
		t.Fatalf("ok sources=%d want 1 (%v)", len(rep.Sources), rep.Sources)
	}
	if len(rep.Failed) != 1 {
		t.Fatalf("failed=%d want 1 (%v)", len(rep.Failed), rep.Failed)
	}
	if rep.Stats.Duplicate == 0 {
		t.Fatalf("expected a duplicate to be counted: %+v", rep.Stats)
	}
}

func TestMergeNodesDropsInvalid(t *testing.T) {
	ok := Node{UUID: "u", Host: "h.example.org", Port: 443, Security: SecurityTLS, SNI: "www.microsoft.com", Transport: TransportTCP}
	dup := ok
	bad := Node{UUID: "", Host: "h.example.org", Port: 443}
	got := MergeNodes([]Node{ok, bad}, []Node{dup})
	if len(got) != 1 {
		t.Fatalf("merged=%d want 1", len(got))
	}
}
