package wgprobe_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/transport/wgprobe"
	"github.com/daniellavrushin/b4/transport/wgprobe/wgprobetest"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestGoldenInitiationVector pins the crypto core against the vector
// captured from wireguard-go and cross-checked by an independent Python
// implementation (Nova ProtonHandshakeVectorTest). Without it, "node
// silent" is indistinguishable from "our own crypto is wrong" — that
// ambiguity already cost one false field conclusion.
func TestGoldenInitiationVector(t *testing.T) {
	staticPriv := [32]byte(mustHex(t, "a01010101010101010101010101010101010101010101010101010101010101f"))
	peerPub := [32]byte(mustHex(t, "6e65ce0be17517110c17d77288ad87e7fd5252dcc7d09b95a39d61db03df832a"))
	ephPriv := [32]byte(mustHex(t, "5011010101010101010101010101010101010101010101010101010101010177"))
	sender := [4]byte(mustHex(t, "deadbeef"))
	ts := [12]byte(mustHex(t, "400000000068aabb00000001"))

	in, err := wgprobe.BuildInitiation(staticPriv, peerPub, ephPriv,
		binary.LittleEndian.Uint32(sender[:]), ts)
	if err != nil {
		t.Fatalf("BuildInitiation: %v", err)
	}
	got := hex.EncodeToString(in.Packet())
	want := "01000000deadbeeffbf34a420f8196539fac3050351a0edd1db01863a2cf37f8c3a7cb583f32cd3f" +
		"b519a958870ca682ae3a896f3048649976246d7f46b656b0a3aefd1d3822e0e6f49737a329f16522" +
		"49abe7d51853da3d55221c9b8c64bb4586625a1146cd951721489c43a6a96171b95a285301d6525a" +
		"9f5c7f44cc942b34e06b636400000000000000000000000000000000"
	if len(in.Packet()) != 148 {
		t.Fatalf("initiation is %d bytes, want 148", len(in.Packet()))
	}
	if got != want {
		t.Fatalf("initiation mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestRoundTripAuthenticatedResponse: a prober initiation + a faithful
// responder double + ConsumeResponse must authenticate. This is the
// strongest local proof the core has both sides right (transcript,
// KDF3/tau, wire layout).
func TestRoundTripAuthenticatedResponse(t *testing.T) {
	resp := wgprobetest.NewResponder()
	staticPriv := [32]byte(mustHex(t, "a01010101010101010101010101010101010101010101010101010101010101f"))
	peerPub := resp.PublicKey()
	ephPriv := [32]byte(mustHex(t, "5011010101010101010101010101010101010101010101010101010101010177"))

	in, err := wgprobe.BuildInitiation(staticPriv, peerPub, ephPriv, 28,
		wgprobe.Tai64n(time.Unix(1770000000, 123456789)))
	if err != nil {
		t.Fatalf("BuildInitiation: %v", err)
	}
	if in.ResponseLooksLike(in.Packet()) {
		t.Fatalf("a type-1 initiation must not match as its own type-2 response")
	}
	packet, err := resp.Respond(in.Packet(), 0x12345678)
	if err != nil {
		t.Fatalf("responder failed to consume our initiation: %v", err)
	}
	if err := in.ConsumeResponse(packet); err != nil {
		t.Fatalf("ConsumeResponse rejected a genuine response: %v", err)
	}
}

// TestConsumeResponseRejectsTampering: every mutation of a genuine
// response — flipped ciphertext bit, wrong echo index, foreign ephemeral —
// must fail authentication or shape/index checks.
func TestConsumeResponseRejectsTampering(t *testing.T) {
	resp := wgprobetest.NewResponder()
	staticPriv := [32]byte(mustHex(t, "a01010101010101010101010101010101010101010101010101010101010101f"))
	peerPub := resp.PublicKey()
	ephPriv := [32]byte(mustHex(t, "5011010101010101010101010101010101010101010101010101010101010177"))
	in, err := wgprobe.BuildInitiation(staticPriv, peerPub, ephPriv, 28,
		wgprobe.Tai64n(time.Unix(1770000000, 123456789)))
	if err != nil {
		t.Fatalf("BuildInitiation: %v", err)
	}
	genuine, err := resp.Respond(in.Packet(), 0x12345678)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	// Flipped ciphertext bit -> authentication failure.
	tampered := append([]byte(nil), genuine...)
	tampered[50] ^= 0x01
	if err := in.ConsumeResponse(tampered); err == nil {
		t.Fatalf("tampered ciphertext accepted")
	}

	// Wrong echo index -> ErrResponseIndex.
	wrongIdx := append([]byte(nil), genuine...)
	wrongIdx[8] ^= 0x01
	if err := in.ConsumeResponse(wrongIdx); err == nil {
		t.Fatalf("wrong receiver echo accepted")
	}

	// Foreign ephemeral (random bytes) -> authentication failure.
	foreign := append([]byte(nil), genuine...)
	copy(foreign[12:44], bytes.Repeat([]byte{0xAB}, 32))
	if err := in.ConsumeResponse(foreign); err == nil {
		t.Fatalf("foreign ephemeral accepted")
	}

	// Truncated / wrong type -> shape failure.
	if err := in.ConsumeResponse(genuine[:60]); err == nil {
		t.Fatalf("truncated response accepted")
	}
	cookie := append([]byte(nil), genuine...)
	cookie[0] = wgprobe.MessageCookieReply
	if err := in.ConsumeResponse(cookie); err == nil {
		t.Fatalf("cookie reply accepted as response")
	}
}

// TestTai64nShape pins the timestamp encoding: big-endian seconds
// offset 0x400000000000000A + unix + big-endian nanoseconds.
func TestTai64nShape(t *testing.T) {
	ts := wgprobe.Tai64n(time.Unix(0x68AAB1, 1))
	want := mustHex(t, "400000000068aabb00000001")
	if !bytes.Equal(ts[:], want) {
		t.Fatalf("tai64n = %x, want %x", ts[:], want)
	}
	zero := wgprobe.Tai64n(time.Unix(0, 0))
	if !bytes.Equal(zero[:], mustHex(t, "400000000000000a00000000")) {
		t.Fatalf("epoch tai64n = %x", zero[:])
	}
}
