package vless

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// The public REALITY corpus encodes pbk as unpadded base64url (Xray:
// base64.RawURLEncoding, 32 bytes). The in-process client must accept that as
// well as 32-byte hex (our own fixtures). Regression for b4x-mi2o.
func TestParseRealityPublicKeyEncodings(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	want := key.PublicKey().Bytes()
	cases := map[string]string{
		"base64url": base64.RawURLEncoding.EncodeToString(want),
		"base64":    base64.StdEncoding.EncodeToString(want),
		"hex":       hex.EncodeToString(want),
	}
	for name, encoded := range cases {
		pub, perr := parseRealityPublicKey(encoded)
		if perr != nil {
			t.Fatalf("%s (%q): %v", name, encoded, perr)
		}
		if !bytes.Equal(pub.Bytes(), want) {
			t.Fatalf("%s: decoded key mismatch", name)
		}
	}
	// A real public-corpus key sample (43-char raw base64url).
	const corpus = "nilJ07r1KZ0-KhmRNYeICXGhM9HeG9uxnRaqjYz3fWg"
	if _, err := parseRealityPublicKey(corpus); err != nil {
		t.Fatalf("corpus key rejected: %v", err)
	}
	for _, bad := range []string{"", "not-a-key", "AAAA", "zzzz"} {
		if _, err := parseRealityPublicKey(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}
