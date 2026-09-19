package warpservice

import (
	"context"
	"testing"
)

// b4x-rnn/b4x-w4c: the SOCKS5 seam builds a TCP-only dialer.
func TestSocks5DialFuncRejectsNonTCP(t *testing.T) {
	df, err := socks5DialFunc("1.2.3.4:1080")
	if err != nil {
		t.Fatalf("build dialer: %v", err)
	}
	if _, err := df(context.Background(), "udp", "example.com:443"); err == nil {
		t.Fatal("udp must be refused (SOCKS5 carries tcp only)")
	}
}

func TestSocks5DialFuncParsesURL(t *testing.T) {
	if _, err := socks5DialFunc("socks5://user:pass@host:1080"); err != nil {
		t.Fatalf("socks5 URL must parse: %v", err)
	}
	if _, err := socks5DialFunc(""); err == nil {
		t.Fatal("empty address must be rejected")
	}
}
