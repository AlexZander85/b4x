package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseConnectRequestValid(t *testing.T) {
	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: keep-alive\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))
	host, port, err := parseConnectRequest(br)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "example.com" || port != 443 {
		t.Fatalf("got %s:%d, want example.com:443", host, port)
	}
}

func TestParseConnectRequestIPv6(t *testing.T) {
	raw := "CONNECT [2606:4700:4700::1111]:443 HTTP/1.1\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))
	host, port, err := parseConnectRequest(br)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "2606:4700:4700::1111" || port != 443 {
		t.Fatalf("got %s:%d", host, port)
	}
}

func TestParseConnectRequestErrors(t *testing.T) {
	cases := map[string]string{
		"bad method":     "GET / HTTP/1.1\r\n\r\n",
		"missing port":   "CONNECT example.com HTTP/1.1\r\n\r\n",
		"bad port":       "CONNECT example.com:notaport HTTP/1.1\r\n\r\n",
		"port range":     "CONNECT example.com:70000 HTTP/1.1\r\n\r\n",
		"short line":     "CONNECT example.com:443\r\n\r\n",
		"eof no headers": "CONNECT example.com:443 HTTP/1.1\r\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(raw))
			if _, _, err := parseConnectRequest(br); err == nil {
				t.Fatalf("expected an error for %q", raw)
			}
		})
	}
}

func TestParseSocksURL(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		user     string
		password string
	}{
		{"1.2.3.4:1080", "1.2.3.4:1080", "", ""},
		{"socks5://1.2.3.4:1080", "1.2.3.4:1080", "", ""},
		{"socks5://u:p@1.2.3.4:1080", "1.2.3.4:1080", "u", "p"},
	}
	for _, c := range cases {
		got, err := parseSocksURL(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if got.host != c.host {
			t.Errorf("%q: host=%q want %q", c.in, got.host, c.host)
		}
		if c.user == "" {
			if got.auth != nil {
				t.Errorf("%q: unexpected auth", c.in)
			}
			continue
		}
		if got.auth == nil || got.auth.User != c.user || got.auth.Password != c.password {
			t.Errorf("%q: auth=%+v", c.in, got.auth)
		}
	}
	if _, err := parseSocksURL("socks5://"); err == nil {
		t.Error("empty host must fail")
	}
}
