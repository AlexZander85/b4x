// Identity.Validate negative matrix (BLOCKER B-1; full matrix extended in
// M3-08). The family-safe AssignedV4 check is the regression fence for the
// v6-in-v4 panic: none of the rejected inputs may panic nor validate.
package transportwarp

import (
	"encoding/pem"
	"testing"
)

// validIdentity builds an Identity that passes Validate, so each negative case
// starts from a field-valid baseline and mutates exactly what it tests.
func validIdentity(t *testing.T) *Identity {
	t.Helper()
	privB64, pubPKIX, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	pinPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubPKIX}))
	return &Identity{
		Format:     IdentityFormatVersion,
		ID:         "dev-abc123",
		Token:      "tok-secret",
		PrivateKey: privB64,
		PinPEM:     pinPEM,
		PinDigest:  PinDigest(pub),
		AssignedV4: "172.16.0.2",
	}
}

func TestValidateAcceptsValidIdentity(t *testing.T) {
	if err := validIdentity(t).Validate(); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
}

func TestValidateRejectsV6InAssignedV4(t *testing.T) {
	inputs := []string{
		"::1",
		"2606:4700::1",
		"2001:db8::",
		"2001:db8::1%eth0",
		"",                    // empty
		"abc",                 // garbage
		"::ffff:203.0.113.7",  // 4-in-6 — decision D1: reject on trusted boundary
		"2001:db8:85a3::8a2e", // arbitrary v6 suffix
		"10.1.2.3 ",           // trailing space (not a valid literal)
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			id := validIdentity(t)
			id.AssignedV4 = in
			if err := id.Validate(); err == nil {
				t.Fatalf("Validate accepted AssignedV4 %q", in)
			}
		})
	}
}
