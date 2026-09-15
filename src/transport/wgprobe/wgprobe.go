// Package wgprobe is a standalone WireGuard Noise-IK handshake prober: it
// builds a spec-exact handshake initiation and verifies the response
// WITHOUT establishing a tunnel. The cryptographic core is a byte-faithful
// port of wireguard-go's device/noise-protocol.go (the vendored
// amneziawg-go tree is the canonical local reference) and the
// Nova ProtonCrypto.buildInitiation lineage, pinned by a golden vector
// captured from wireguard-go itself (ProtonHandshakeVectorTest).
//
// Why a prober at all: WireGuard SILENTLY drops a bad handshake exactly
// like an unreachable node, and a TCP connect proves nothing about the
// UDP/WireGuard path the real tunnel rides. A completed Noise-IK exchange
// (initiation -> authenticated type-2 response) is the strongest liveness
// + identity + reachability signal available without paying for a full
// session, which is precisely what endpoint ranking needs.
//
// Layout constants (vanilla WireGuard wire format, little-endian):
//
//	initiation (148 B): type[0:4]=1 | sender[4:8] | eph[8:40] |
//	                    encStatic[40:88] | encTimestamp[88:116] |
//	                    mac1[116:132] | mac2[132:148]
//	response  (92 B):   type[0:4]=2 | sender[4:8] | receiver[8:12] |
//	                    eph[12:44] | encEmpty[44:60] | mac1 | mac2
//
// The response RECEIVER field echoes the initiation's SENDER index — that
// is how the prober matches a response to its own attempt on a socket that
// may also see unrelated datagrams (cookie replies, cover echoes).
//
// Hash/chain-key discipline (wireguard-go exact):
//   - after building the initiation, the transcript hash INCLUDES the
//     encrypted timestamp (CreateMessageInitiation mixes it LAST);
//   - the psk stage of the response is KDF3: (chainKey, tau, key), and TAU
//     is mixed into the hash before the empty payload is decrypted with
//     AD = hash;
//   - mac1 = keyed BLAKE2s-128 with key BLAKE2s("mac1----" || peerPub).
package wgprobe

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Wire-format constants (vanilla WireGuard; AWG header-morphed types are
// out of scope — both Proton and cf-warp peers speak vanilla headers).
const (
	MessageInitiationType uint32 = 1
	MessageResponseType   uint32 = 2
	MessageCookieReply    byte   = 3

	InitiationSize = 148
	ResponseMinLen = 92 // a shorter datagram cannot be a type-2 response
)

// Protocol transcript seeds (wireguard-go noise-protocol.go init()).
var (
	noiseConstruction = []byte("Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s")
	wgIdentifier      = []byte("WireGuard v1 zx2c4 Jason@zx2c4.com")
	labelMAC1         = []byte("mac1----")

	initialChainKey = blake2s.Sum256(noiseConstruction)
	initialHash     = blake2sInitialHash()
)

// InitialChainKey and InitialHash expose the Noise transcript seeds so
// integration harnesses (wgprobetest's responder double, future e2e fake
// edges) can replay the exact protocol state without re-deriving it.
func InitialChainKey() [32]byte { return initialChainKey }

// InitialHash returns the post-identifier transcript seed (see package doc).
func InitialHash() [32]byte { return initialHash }

func blake2sInitialHash() [32]byte {
	var h [32]byte
	mac, _ := blake2s.New256(nil)
	mac.Write(initialChainKey[:])
	mac.Write(wgIdentifier)
	mac.Sum(h[:0])
	return h
}

// zeroPSK: the probe authenticates with the identity's static key only;
// Proton and cf-warp both run psk-less peers (psk2 = 32 zero bytes on the
// wire, exactly what the engine itself sends).
var zeroPSK [32]byte

var (
	// ErrBadKeys is returned for malformed 32-byte inputs.
	ErrBadKeys = errors.New("wgprobe: keys must be 32 bytes")
	// ErrResponseShape: datagram is not a plausibly-shaped type-2 response.
	ErrResponseShape = errors.New("wgprobe: bad response shape")
	// ErrResponseIndex: receiver field does not echo our sender index.
	ErrResponseIndex = errors.New("wgprobe: response for a different handshake")
	// ErrResponseAuth: Noise authentication of the response failed.
	ErrResponseAuth = errors.New("wgprobe: response failed Noise authentication")
)

// Keys is the probe identity: our static X25519 private key (the same one
// the engine derives from the Proton seed) and the peer's static public.
type Keys struct {
	StaticPriv [32]byte
	PeerPub    [32]byte
}

// NewKeys validates and copies the raw key pair.
func NewKeys(staticPriv, peerPub []byte) (*Keys, error) {
	if len(staticPriv) != 32 || len(peerPub) != 32 {
		return nil, ErrBadKeys
	}
	k := &Keys{}
	copy(k.StaticPriv[:], staticPriv)
	copy(k.PeerPub[:], peerPub)
	return k, nil
}

// PublicKey derives the static public half (X25519 basepoint mult).
func (k *Keys) PublicKey() ([32]byte, error) {
	pub, err := curve25519.X25519(k.StaticPriv[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, fmt.Errorf("wgprobe: static key unusable: %w", err)
	}
	var out [32]byte
	copy(out[:], pub)
	return out, nil
}

// ---------------------------------------------------------------------------
// WireGuard KDF / hash / AEAD primitives (HMAC-BLAKE2s based).
// ---------------------------------------------------------------------------

func newBlake2s() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// Hash folds parts into one BLAKE2s-256 digest (wireguard-go mixHash).
func Hash(parts ...[]byte) [32]byte {
	h := newBlake2s()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// HMAC is HMAC-BLAKE2s-256 (wireguard-go HMAC1/HMAC2).
func HMAC(key []byte, parts ...[]byte) [32]byte {
	m := hmac.New(newBlake2s, key)
	for _, p := range parts {
		m.Write(p)
	}
	var out [32]byte
	m.Sum(out[:0])
	return out
}

// KDF derives count output keys: prk = HMAC(key, input); out[i] =
// HMAC(prk, out[i-1] || i+1) with out[-1] empty. (wireguard-go KDF1/2/3.)
func KDF(key, input []byte, count int) [][32]byte {
	prk := HMAC(key, input)
	out := make([][32]byte, count)
	var prev []byte
	for i := 0; i < count; i++ {
		var msg []byte
		msg = append(msg, prev...)
		msg = append(msg, byte(i+1))
		out[i] = HMAC(prk[:], msg)
		prev = out[i][:]
	}
	return out
}

// AEADSeal encrypts plain under key at counter 0 with AD=ad
// (chacha20poly1305, zero nonce — the only counter a handshake uses).
func AEADSeal(key [32]byte, plain, ad []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, make([]byte, chacha20poly1305.NonceSize), plain, ad), nil
}

// AEADOpen is AEADSeal's inverse; a failed open is an authentication
// failure, not a transport error.
func AEADOpen(key [32]byte, sealed, ad []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return a.Open(nil, make([]byte, chacha20poly1305.NonceSize), sealed, ad)
}

// mac1Key is the keyed hash key for the first MAC: BLAKE2s("mac1----" ||
// peerPub). The peer public here is the key of whoever READS the mac —
// the initiator MACs against the responder's static, and vice versa.
func mac1Key(peerPub [32]byte) [32]byte {
	return Hash(labelMAC1, peerPub[:])
}

// mac1 computes the 16-byte keyed BLAKE2s over the packet head.
func mac1(peerPub [32]byte, head []byte) ([]byte, error) {
	key := mac1Key(peerPub)
	h, err := blake2s.New128(key[:])
	if err != nil {
		return nil, err
	}
	h.Write(head)
	return h.Sum(nil), nil
}

// Tai64n renders the 12-byte WireGuard timestamp: big-endian seconds since
// the TAI64 epoch (offset 0x400000000000000A) + big-endian nanoseconds.
func Tai64n(now time.Time) [12]byte {
	now = now.UTC()
	var out [12]byte
	binary.BigEndian.PutUint64(out[:8], uint64(0x400000000000000A+now.Unix()))
	binary.BigEndian.PutUint32(out[8:], uint32(now.Nanosecond()))
	return out
}

// ---------------------------------------------------------------------------
// Initiation construction.
// ---------------------------------------------------------------------------

// Initiation is one built handshake attempt plus the transcript state
// needed to authenticate the response. Deterministic for fixed inputs —
// the golden test relies on that.
type Initiation struct {
	packet [InitiationSize]byte

	sender uint32 // index we placed in [4:8]; the response echoes it

	// transcript state persisted after the initiation, exactly the fields
	// wireguard-go keeps in Handshake after CreateMessageInitiation:
	hash       [32]byte // includes encTimestamp (mixed last)
	chainKey   [32]byte // after the ss KDF2
	ephPriv    [32]byte
	staticPriv [32]byte
	staticPub  [32]byte
	peerPub    [32]byte
}

// BuildInitiation constructs the 148-byte initiation from fixed inputs.
// staticPriv is our static private key; peerPub the responder's static
// public; ephPriv the ephemeral private (caller-owned randomness so tests
// pin it); senderIndex the 32-bit index echoed by the response; ts the
// TAI64N timestamp. This is the byte-exact analogue of
// ProtonCrypto.buildInitiation / wireguard-go CreateMessageInitiation.
func BuildInitiation(staticPriv, peerPub, ephPriv [32]byte, senderIndex uint32, ts [12]byte) (*Initiation, error) {
	staticPub, err := curve25519.X25519(staticPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("wgprobe: static key unusable: %w", err)
	}
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("wgprobe: ephemeral key unusable: %w", err)
	}

	in := &Initiation{
		sender:     senderIndex,
		ephPriv:    ephPriv,
		staticPriv: staticPriv,
		staticPub:  [32]byte(staticPub),
		peerPub:    peerPub,
	}

	// Transcript: ck0/h0 seeds -> peer static -> ephemeral.
	ck := initialChainKey
	h := Hash(initialHash[:], peerPub[:])
	ck = KDF(ck[:], ephPub[:], 1)[0]
	h = Hash(h[:], ephPub[:])

	// es = DH(e_i, s_r); encrypt our static under the derived key.
	es, err := curve25519.X25519(ephPriv[:], peerPub[:])
	if err != nil {
		return nil, fmt.Errorf("wgprobe: es DH: %w", err)
	}
	d := KDF(ck[:], es, 2)
	ck = d[0]
	encStatic, err := AEADSeal(d[1], staticPub, h[:])
	if err != nil {
		return nil, err
	}
	h = Hash(h[:], encStatic)

	// ss = DH(s_i, s_r); encrypt the timestamp under the derived key.
	ss, err := curve25519.X25519(staticPriv[:], peerPub[:])
	if err != nil {
		return nil, fmt.Errorf("wgprobe: ss DH: %w", err)
	}
	d = KDF(ck[:], ss, 2)
	ck = d[0]
	encTimestamp, err := AEADSeal(d[1], ts[:], h[:])
	if err != nil {
		return nil, err
	}
	// wireguard-go mixes the encrypted timestamp into the persistent hash
	// AFTER the packet body is built (it is the last transcript step of
	// message 1); the response authentication below depends on it.
	h = Hash(h[:], encTimestamp)

	in.hash = h
	in.chainKey = ck

	// Wire assembly.
	head := make([]byte, 0, InitiationSize-32)
	head = binary.LittleEndian.AppendUint32(head, MessageInitiationType)
	head = binary.LittleEndian.AppendUint32(head, senderIndex)
	head = append(head, ephPub[:]...)
	head = append(head, encStatic...)
	head = append(head, encTimestamp...)
	m1, err := mac1(peerPub, head)
	if err != nil {
		return nil, err
	}
	copy(in.packet[:len(head)], head)
	copy(in.packet[len(head):len(head)+16], m1)
	// mac2 stays zero: it is only filled in response to a cookie request,
	// which never happens on a first packet.
	return in, nil
}

// Packet returns the wire bytes of the initiation.
func (in *Initiation) Packet() []byte { return in.packet[:] }

// SenderIndex is the sender index placed in [4:8] (for response matching).
func (in *Initiation) SenderIndex() uint32 { return in.sender }

// RandomIndex draws a nonzero sender index from r (crypto/rand in
// production; tests inject a fixed reader for determinism).
func RandomIndex(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	idx := binary.LittleEndian.Uint32(b[:])
	if idx == 0 {
		idx = 1
	}
	return idx, nil
}

// ---------------------------------------------------------------------------
// Response verification (initiator side of message 2).
// ---------------------------------------------------------------------------

// ResponseLooksLike reports whether p is shaped like a type-2 response for
// our sender index (cheap pre-filter before the authenticated consume).
func (in *Initiation) ResponseLooksLike(p []byte) bool {
	return len(p) >= ResponseMinLen &&
		binary.LittleEndian.Uint32(p[0:4]) == MessageResponseType &&
		binary.LittleEndian.Uint32(p[8:12]) == in.sender
}

// ConsumeResponse authenticates a type-2 response against the initiation
// transcript. It re-derives the full responder-side key schedule:
//
//	ee = DH(e_i, e_r); se = DH(s_i, e_r); psk2 via KDF3 with tau mixed
//	into the hash; the empty payload must open with AD = hash.
//
// A passing response proves the peer holds the static private key we
// probed — silence or failure says nothing, but success is airtight.
func (in *Initiation) ConsumeResponse(resp []byte) error {
	if !in.ResponseLooksLike(resp) {
		if len(resp) >= 12 && binary.LittleEndian.Uint32(resp[0:4]) == MessageResponseType &&
			binary.LittleEndian.Uint32(resp[8:12]) != in.sender {
			return ErrResponseIndex
		}
		return ErrResponseShape
	}
	var ephR [32]byte
	copy(ephR[:], resp[12:44])
	encEmpty := resp[44:60]

	// e: mix the responder ephemeral into both chains.
	hash := Hash(in.hash[:], ephR[:])
	chainKey := KDF(in.chainKey[:], ephR[:], 1)[0]

	// ee = DH(e_i, e_r).
	ee, err := curve25519.X25519(in.ephPriv[:], ephR[:])
	if err != nil {
		return fmt.Errorf("wgprobe: ee DH: %w", err)
	}
	chainKey = KDF(chainKey[:], ee, 1)[0]

	// se = DH(s_i, e_r).
	se, err := curve25519.X25519(in.staticPriv[:], ephR[:])
	if err != nil {
		return fmt.Errorf("wgprobe: se DH: %w", err)
	}
	chainKey = KDF(chainKey[:], se, 1)[0]

	// psk2: KDF3 -> (chainKey, tau, key); tau mixes into the hash.
	d := KDF(chainKey[:], zeroPSK[:], 3)
	tau, key := d[1], d[2]
	hash = Hash(hash[:], tau[:])

	// Authenticate: the empty payload must open under AD = hash.
	plain, err := AEADOpen(key, encEmpty, hash[:])
	if err != nil {
		return ErrResponseAuth
	}
	if len(plain) != 0 {
		return ErrResponseAuth
	}
	return nil
}

// StaticPub copies out our static public key (test doubles use it).
func (in *Initiation) StaticPub() [32]byte { return in.staticPub }

// PeerPub copies out the peer static public key.
func (in *Initiation) PeerPub() [32]byte { return in.peerPub }

// KeyedBlake2s128 is the 16-byte keyed BLAKE2s used for the WireGuard
// packet MACs; exposed so responder doubles (wgprobetest) can stamp mac1.
func KeyedBlake2s128(key [32]byte, data []byte) []byte {
	h, err := blake2s.New128(key[:])
	if err != nil {
		// unreachable for a 32-byte key
		return nil
	}
	h.Write(data)
	return h.Sum(nil)
}
