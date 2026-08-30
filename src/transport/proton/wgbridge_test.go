package proton

import (
	"testing"
)

// TestWGIdentityReservedHookNil is the acceptance-checklist red line
// (patch-plan §10.3, design §11.3 via E-WG): the reserved routing bytes ride
// ONLY on Cloudflare peers. A Proton identity MUST project with
// cf_warp=false and a NIL datagram hook — the reserved bytes stay zero on
// the wire against the vanilla Proton edge.
func TestWGIdentityReservedHookNil(t *testing.T) {
	id := testIdentity(t)
	node := Node{EntryIP: "127.0.0.1", PeerPubKey: validPeerKey(t)}
	wgid, err := id.WGIdentity(node)
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	if wgid.CFWarp {
		t.Fatal("proton identity must project with cf_warp=false")
	}
	hook, err := wgid.DatagramHookOrNil()
	if err != nil {
		t.Fatalf("hook derivation: %v", err)
	}
	if hook != nil {
		t.Fatal("reserved hook MUST be nil for the proton identity (red line §10.3)")
	}


	// The projection must also pass the engine's validation.
	if err := wgid.Validate(); err != nil {
		t.Fatalf("engine validation: %v", err)
	}

	// The WG key derives from the seed deterministically.
	kp := DeriveKeyPair(testSeed)
	if kp.WGPrivateKeyB64 == "" {
		t.Fatal("empty derived key")
	}
}

func validPeerKey(t *testing.T) string {
	t.Helper()
	seed, err := RandomSeed(crandLikeReader())
	if err != nil {
		t.Fatal(err)
	}
	return DeriveKeyPair(seed).WGPubKeyB64
}

func crandLikeReader() *xorshiftReader { return &xorshiftReader{state: 7} }

type xorshiftReader struct{ state uint64 }

func (r *xorshiftReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state ^= r.state << 13
		r.state ^= r.state >> 7
		r.state ^= r.state << 17
		p[i] = byte(r.state)
	}
	return len(p), nil
}
