package transportwarp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestGenerateAndParseClientKey(t *testing.T) {
	privB64, pubDER, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatalf("parse own key: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != string(pubDER) {
		t.Fatal("public key roundtrip mismatch")
	}
}

func TestParseClientKeyRejectsGarbage(t *testing.T) {
	if _, err := ParseClientKeyB64("not-base64!!!"); err == nil {
		t.Fatal("expected error for non-base64")
	}
	// base64 of a RSA-ish DER blob must fail as EC key.
	if _, err := ParseClientKeyB64("MIIB"); err == nil {
		t.Fatal("expected error for truncated DER")
	}
}

func TestPinPEMParseAndDigest(t *testing.T) {
	priv := newTestKey(t)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	gotPub, digest, err := ParsePublicKeyPEM(string(pemStr))
	if err != nil {
		t.Fatal(err)
	}
	if !gotPub.Equal(&priv.PublicKey) {
		t.Fatal("pin pubkey mismatch")
	}
	if len(digest) != 64 { // sha256 hex
		t.Fatalf("digest len %d", len(digest))
	}
	_, _, err = ParsePublicKeyPEM("junk")
	if err == nil {
		t.Fatal("expected PEM decode failure")
	}
}

func TestPrepareTLSConfigRequiresPin(t *testing.T) {
	priv := newTestKey(t)
	cert, err := ClientCertificate(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareTLSConfig(cert, "sni", nil, nil); err == nil {
		t.Fatal("insecure mode must be forbidden")
	}
}

func TestTLSConfigPinVerification(t *testing.T) {
	serverKey := newTestKey(t)
	clientCert, err := ClientCertificate(newTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := PrepareTLSConfig(clientCert, "consumer-masque.cloudflareclient.com", &serverKey.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	serverDER := selfSignedDERForTest(t, serverKey)

	// matching pin passes
	if err := cfg.VerifyPeerCertificate([][]byte{serverDER}, nil); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}

	// different key fails with ErrPinMismatch
	if err := cfg.VerifyPeerCertificate([][]byte{selfSignedDERForTest(t, newTestKey(t))}, nil); err == nil {
		t.Fatal("mismatched pin accepted")
	} else if err != ErrPinMismatch {
		t.Fatalf("want ErrPinMismatch, got %v", err)
	}

	// extra pin set accepts alternative backend key
	alt := newTestKey(t)
	cfg2, _ := PrepareTLSConfig(clientCert, "sni", &serverKey.PublicKey,
		map[string]bool{PinDigest(&alt.PublicKey): true})
	if err := cfg2.VerifyPeerCertificate([][]byte{selfSignedDERForTest(t, alt)}, nil); err != nil {
		t.Fatalf("extra pin rejected: %v", err)
	}
	// and the primary still wins
	if err := cfg2.VerifyPeerCertificate([][]byte{serverDER}, nil); err != nil {
		t.Fatalf("primary pin rejected when extras present: %v", err)
	}
}
