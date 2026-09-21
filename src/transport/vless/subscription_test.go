package vless

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetch(t *testing.T) {
	body := realityURI + "\n" + wsURI + "\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Errorf("missing user agent")
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := Fetch(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body mismatch")
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer bad.Close()
	if _, err := Fetch(context.Background(), bad.Client(), bad.URL); err == nil {
		t.Fatal("non-2xx must error")
	}
}

func TestFetchRejectsOversize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("A"), 1<<20)
		for i := 0; i < (MaxSubscriptionBytes>>20)+2; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("oversized body must error")
	}
}

func TestDecodeBody(t *testing.T) {
	plain := realityURI + "\n" + wsURI
	if got := DecodeBody([]byte(plain)); len(got) != 2 {
		t.Fatalf("plain lines=%d want 2", len(got))
	}

	std := base64.StdEncoding.EncodeToString([]byte(plain))
	if got := DecodeBody([]byte(std)); len(got) != 2 {
		t.Fatalf("std base64 lines=%d want 2", len(got))
	}

	urlSafe := base64.RawURLEncoding.EncodeToString([]byte(plain))
	if got := DecodeBody([]byte(urlSafe)); len(got) != 2 {
		t.Fatalf("url-safe base64 lines=%d want 2", len(got))
	}

	jsonDoc := `{"outbounds":[{"type":"vless","server":"h.example.org","server_port":443,"uuid":"u","tls":{"enabled":true,"server_name":"www.microsoft.com"}}]}`
	got := DecodeBody([]byte(jsonDoc))
	if len(got) != 1 || !strings.HasPrefix(got[0], "{") {
		t.Fatalf("json must pass through as one entry: %v", got)
	}
}

func TestParseSubscriptionMixed(t *testing.T) {
	body := strings.Join([]string{
		realityURI,
		"trojan://x@h.example.org:443#t", // other protocol
		"vless://broken@host",            // bad (no port)
		wsURI,
	}, "\n")
	raw := base64.StdEncoding.EncodeToString([]byte(body))
	nodes, st := ParseSubscription([]byte(raw))
	if len(nodes) != 2 {
		t.Fatalf("nodes=%d want 2 (stats=%+v)", len(nodes), st)
	}
	if st.Other != 1 || st.Bad != 1 {
		t.Fatalf("stats=%+v want other=1 bad=1", st)
	}
}

func TestResolveSourcesAndRedact(t *testing.T) {
	all := ResolveSources(true, []string{"https://sub.example.org/token/abc"})
	if len(all) != len(bundledSources)+1 {
		t.Fatalf("resolved=%d want %d", len(all), len(bundledSources)+1)
	}
	only := ResolveSources(false, []string{"https://sub.example.org/x", "https://sub.example.org/x"})
	if len(only) != 1 {
		t.Fatalf("dedup failed: %v", only)
	}
	if r := RedactURL("https://sub.example.org/token/secret?k=1"); strings.Contains(r, "secret") || strings.Contains(r, "k=1") {
		t.Fatalf("redaction leaked secret: %q", r)
	}
}
