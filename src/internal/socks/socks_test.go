package socks

import (
	"context"
	"testing"
)

// b4x-rnn/b4x-w4c: the SOCKS5 seam builds a TCP-only dialer.
func TestDialFuncRejectsNonTCP(t *testing.T) {
	df, err := DialFunc("1.2.3.4:1080")
	if err != nil {
		t.Fatalf("build dialer: %v", err)
	}
	if _, err := df(context.Background(), "udp", "example.com:443"); err == nil {
		t.Fatal("udp must be refused (SOCKS5 carries tcp only)")
	}
}

func TestParseAddr(t *testing.T) {
	a, err := ParseAddr("socks5://u:p@host.example:1080")
	if err != nil || a.Host != "host.example" || a.Port != 1080 || a.User != "u" || a.Pass != "p" {
		t.Fatalf("ParseAddr = %+v, %v", a, err)
	}
	if _, err := ParseAddr("1.2.3.4:1080"); err != nil {
		t.Fatalf("plain host:port rejected: %v", err)
	}
	for _, bad := range []string{"", "host", "host:0", "host:99999"} {
		if _, err := ParseAddr(bad); err == nil {
			t.Fatalf("ParseAddr(%q) must error", bad)
		}
	}
}

func TestDialFuncParsesURL(t *testing.T) {
	if _, err := DialFunc("socks5://user:pass@host:1080"); err != nil {
		t.Fatalf("socks5 URL must parse: %v", err)
	}
	if _, err := DialFunc(""); err == nil {
		t.Fatal("empty address must be rejected")
	}
}
