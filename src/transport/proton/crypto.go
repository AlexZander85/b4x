// Package proton implements the E-PROTON control plane (design v1): the
// credentialless Proton session, the client-key registration, the free-tier
// node catalog and the QUIC-Initial I1 generator that feeds the shared
// transport/wg data-plane engine.
//
// Crypto core (design §1.5, port of Nova ProtonCrypto.kt:39-77 — all three
// references agree byte-for-byte): ONE ed25519 identity is registered with
// Proton, and the WireGuard key is DERIVED from the same 32-byte seed. The
// seed is the single secret that ever touches the disk (identity slot 0600);
// tokens live in the same slot, the WG private key never does — it is
// re-derived on every use.
//
//	ed25519 pub  -> PEM SubjectPublicKeyInfo (fixed DER prefix
//	                "MCowBQYDK2VwAyEA" = 12 bytes 30 2A 30 05 06 03 2B 65 70
//	                03 21 00 + 32-byte key) -> ClientPublicKey field;
//	WG private   -> clamp(SHA-512(seed)[0:32]) — the standard
//	                crypto_sign_ed25519_sk_to_curve25519 conversion;
//	WG public    -> curve25519.X25519(priv, basepoint).
//
// The server performs the same conversion over the registered public half,
// so ONE registration works for every Proton server at once (the key is not
// bound to a node). Changing the certificate never changes the WG key — a
// re-issue does not tear the tunnel down.
package proton

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// ed25519SPKIBodyPrefix is the fixed base64 DER header of an Ed25519
// SubjectPublicKeyInfo (12 bytes) that precedes the 32-byte key in the
// base64 body of the PEM. Proton's /vpn/v1/certificate accepts exactly this
// shape (Nova ED25519_SPKI_PREFIX).
const ed25519SPKIBodyPrefix = "MCowBQYDK2VwAyEA"

// KeyPair is everything derived from one seed. Seed is the ONLY secret and
// never leaves this package / the identity store; the rest is wire or
// diagnostic material.
type KeyPair struct {
	Seed [32]byte
	// Ed25519PubPEM is the full PEM ("-----BEGIN PUBLIC KEY-----" wrapped)
	// SubjectPublicKeyInfo — the value that goes into ClientPublicKey.
	Ed25519PubPEM string
	// WGPrivateKeyB64 is the clamped x25519 private key (base64, raw std) —
	// the wg config private_key.
	WGPrivateKeyB64 string
	// WGPubKeyB64 is the derived x25519 public key (base64) — diagnostics
	// only; the server derives it from the registered ed25519 half itself.
	WGPubKeyB64 string
}

// DeriveKeyPair derives the whole identity from one 32-byte seed (design
// §1.5). Deterministic by construction: the same seed always yields the same
// ed25519 PEM and the same WG keypair, so identity validation can re-derive
// and compare.
func DeriveKeyPair(seed [32]byte) KeyPair {
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	body := ed25519SPKIBodyPrefix + base64.StdEncoding.EncodeToString(pub)
	pem := "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n"

	wgPriv := wgPrivateKeyFromSeed(seed)
	wgPub, err := curve25519.X25519(wgPriv[:], curve25519.Basepoint)
	if err != nil {
		// Unreachable for a clamped 32-byte scalar: the input is always in
		// range. Surface an empty key rather than panicking.
		wgPub = make([]byte, 32)
	}
	return KeyPair{
		Seed:            seed,
		Ed25519PubPEM:   pem,
		WGPrivateKeyB64: base64.StdEncoding.EncodeToString(wgPriv[:]),
		WGPubKeyB64:     base64.StdEncoding.EncodeToString(wgPub),
	}
}

// RandomSeed reads 32 bytes of randomness from r (production: crypto/rand;
// tests: a fixed reader for golden determinism).
func RandomSeed(r io.Reader) ([32]byte, error) {
	var seed [32]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		return seed, fmt.Errorf("proton: reading seed: %w", err)
	}
	return seed, nil
}

// wgPrivateKeyFromSeed computes clamp(SHA-512(seed)[0:32]) — the ed25519 ->
// x25519 private-key conversion every reference implements identically
// (priv[0] &= 248; priv[31] &= 127; priv[31] |= 64).
func wgPrivateKeyFromSeed(seed [32]byte) [32]byte {
	h := sha512.Sum512(seed[:])
	var priv [32]byte
	copy(priv[:], h[:32])
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	return priv
}
