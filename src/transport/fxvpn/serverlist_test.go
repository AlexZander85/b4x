package fxvpn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const testServerlistBody = `{"data":[
 {"name":"Germany","code":"DE","cities":[{"name":"Berlin","code":"BER","servers":[
   {"hostname":"ber1.m1.fastly-masque.net","port":2499}
 ]}]},
 {"name":"Japan","code":"JP","cities":[{"name":"Tokyo","code":"TYO","servers":[
   {"hostname":"tyo1.m1.fastly-masque.net","port":2499,
    "protocols":[{"name":"connect","host":"tyo-connect.example","port":8443},
                 {"name":"masque","host":"tyo-masque.example","port":443,"templateString":"https://t/{target_host}/{target_port}"}]},
   {"hostname":"bkk1.m1.fastly-masque.net","port":2499,"quarantined":true}
 ]}]},
 {"not-a-country":true}
]}`

func TestParseServerListBothRecordShapes(t *testing.T) {
	countries, err := ParseServerList([]byte(testServerlistBody))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(countries) != 2 {
		t.Fatalf("countries = %d, want 2 (junk record skipped)", len(countries))
	}

	// Bare record (no protocols[]) defaults to connect on hostname:port.
	de := ConnectCandidates(countries, "de", "", "")
	if len(de) != 1 || de[0].Hostname != "ber1.m1.fastly-masque.net" || de[0].Port != 2499 || de[0].Scheme != "https" {
		t.Fatalf("bare normalization broken: %+v", de)
	}
	if de[0].CountryCode != "DE" || de[0].CityCode != "BER" {
		t.Fatalf("location metadata lost: %+v", de[0])
	}

	jp := ConnectCandidates(countries, "JP", "", "")
	// tyo1: connect proto overrides host/port; masque ignored; quarantined excluded.
	if len(jp) != 1 || jp[0].Hostname != "tyo-connect.example" || jp[0].Port != 8443 {
		t.Fatalf("connect-proto override broken: %+v", jp)
	}
}

func TestConnectCandidatesFilters(t *testing.T) {
	countries, err := ParseServerList([]byte(testServerlistBody))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if all := ConnectCandidates(countries, "", "", ""); len(all) != 2 {
		t.Fatalf("all = %d, want 2", len(all))
	}
	if city := ConnectCandidates(countries, "", "tyo", ""); len(city) != 1 || city[0].CityCode != "TYO" {
		t.Fatalf("city filter: %+v", city)
	}
	if host := ConnectCandidates(countries, "", "", "ber1.m1.fastly-masque.net"); len(host) != 1 {
		t.Fatalf("host filter: %+v", host)
	}
	if _, ok := FindHost(countries, "nope.invalid"); ok {
		t.Fatal("unknown host must not resolve")
	}
	if c, ok := FindHost(countries, "BER1.M1.FASTLY-MASQUE.NET"); !ok || c.Port != 2499 {
		t.Fatal("host match must be case-insensitive")
	}
}

func TestServerlistCacheETagRoundAndStaleFallback(t *testing.T) {
	var reqs int32
	lastIfNoneMatch := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqs, 1)
		lastIfNoneMatch = r.Header.Get("If-None-Match")
		if atomic.LoadInt32(&reqs) == 1 {
			w.Header().Set("ETag", `"v7"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(testServerlistBody))
			return
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	cp := newTestCP(t, "")
	path := filepath.Join(t.TempDir(), "serverlist.json")
	sc, err := NewServerlistCache(cp, path)
	if err != nil {
		t.Fatalf("cache init: %v", err)
	}
	cp.EP.RemoteSettings = srv.URL

	got, fromCache, err := sc.Get(context.Background())
	if err != nil || fromCache || len(got) != 2 {
		t.Fatalf("first get: n=%d cache=%v err=%v", len(got), fromCache, err)
	}

	// Within TTL: no network.
	if _, fromCache, err := sc.Get(context.Background()); err != nil || !fromCache {
		t.Fatalf("TTL hit expected, cache=%v err=%v", fromCache, err)
	}
	if atomic.LoadInt32(&reqs) != 1 {
		t.Fatalf("requests = %d, want 1 within TTL", reqs)
	}

	// Expire by rewinding FetchedAt in the persisted file, then reload.
	if lastIfNoneMatch != "" {
		t.Fatalf("premature If-None-Match: %q", lastIfNoneMatch)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted cache: %v", err)
	}
	var stored cachedServerlist
	if err := json.Unmarshal(blob, &stored); err != nil {
		t.Fatalf("persisted cache unreadable: %v", err)
	}
	stored.FetchedAt = stored.FetchedAt.Add(-sc.TTL - time.Minute)
	rewound, _ := json.Marshal(stored)
	if err := os.WriteFile(path, rewound, 0o600); err != nil {
		t.Fatal(err)
	}

	sc2, err := NewServerlistCache(cp, path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got2, _, err := sc2.Get(context.Background())
	if err != nil || len(got2) != 2 {
		t.Fatalf("304 round: n=%d err=%v", len(got2), err)
	}
	if lastIfNoneMatch != `"v7"` {
		t.Fatalf(`If-None-Match = %q, want "v7"`, lastIfNoneMatch)
	}
	if atomic.LoadInt32(&reqs) != 2 {
		t.Fatalf("requests = %d after conditional round, want 2", reqs)
	}

	// Dead edge + present cache => stale fallback wins over error.
	cp.EP.RemoteSettings = "http://127.0.0.1:1/nope"
	if _, fromCache, err := sc2.Get(context.Background()); err != nil || !fromCache {
		t.Fatalf("stale fallback failed: cache=%v err=%v", fromCache, err)
	}
}

func TestServerlistCacheCorruptQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serverlist.json")
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	cp := newTestCP(t, "")
	if _, err := NewServerlistCache(cp, path); !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("want ErrStoreCorrupt, got %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt cache not quarantined: %v", err)
	}
}
