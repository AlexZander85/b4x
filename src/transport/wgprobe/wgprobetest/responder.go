// Package wgprobetest ships a minimal in-process vanilla-WireGuard
// RESPONDER double for integration tests of higher layers (proton probe
// ranking, warp endpoint scans). It completes the Noise-IK exchange from
// the responder side exactly like wireguard-go's ConsumeMessageInitiation
// + CreateMessageResponse, using the exported wgprobe primitive kit.
//
// It is a TEST package by contract: never imported from production code.
package wgprobetest

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/daniellavrushin/b4/transport/wgprobe"
	"golang.org/x/crypto/curve25519"
)

// Responder is a fixed-static-key WireGuard responder double.
type Responder struct {
	staticPriv [32]byte
}

// NewResponder generates a clamped random static key pair.
func NewResponder() *Responder {
	var r Responder
	if _, err := rand.Read(r.staticPriv[:]); err != nil {
		panic(fmt.Sprintf("wgprobetest: rand: %v", err))
	}
	r.staticPriv[0] &= 248
	r.staticPriv[31] &= 127
	r.staticPriv[31] |= 64
	return &r
}

// NewResponderKey builds a responder around a fixed private key (golden
// determinism in tests).
func NewResponderKey(priv [32]byte) *Responder {
	r := &Responder{staticPriv: priv}
	r.staticPriv[0] &= 248
	r.staticPriv[31] &= 127
	r.staticPriv[31] |= 64
	return r
}

// PublicKey returns the responder's static public key (the "peer key" the
// initiator must be configured with).
func (r *Responder) PublicKey() [32]byte {
	pub, err := curve25519.X25519(r.staticPriv[:], curve25519.Basepoint)
	if err != nil {
		panic(fmt.Sprintf("wgprobetest: static key: %v", err))
	}
	return [32]byte(pub)
}

// Respond consumes a 148-byte initiation and produces the 92-byte type-2
// response. senderIndex is placed in [4:8]; the receiver echo of the
// initiator's sender index lands at [8:12] (wireguard-go MessageResponse
// layout: Type, Sender, Receiver). mac1 is computed against the
// INITIATOR's static key (whose holder reads that mac); mac2 stays zero.
func (r *Responder) Respond(init []byte, senderIndex uint32) ([]byte, error) {
	if len(init) != wgprobe.InitiationSize {
		return nil, fmt.Errorf("wgprobetest: initiation is %d bytes, want %d",
			len(init), wgprobe.InitiationSize)
	}
	var ephI [32]byte
	copy(ephI[:], init[8:40])
	encStatic := init[40:88]
	encTimestamp := init[88:116]

	// Transcript through the encrypted static (ConsumeMessageInitiation).
	respPub := r.PublicKey()
	initialHash := wgprobe.InitialHash()
	initialChainKey := wgprobe.InitialChainKey()
	hash := wgprobe.Hash(initialHash[:], respPub[:])
	hash = wgprobe.Hash(hash[:], ephI[:])
	chainKey := wgprobe.KDF(initialChainKey[:], ephI[:], 1)[0]

	// es = DH(s_r, e_i): decrypt the initiator's static.
	es, err := curve25519.X25519(r.staticPriv[:], ephI[:])
	if err != nil {
		return nil, err
	}
	d := wgprobe.KDF(chainKey[:], es[:], 2)
	chainKey = d[0]
	initStaticPub, err := wgprobe.AEADOpen(d[1], encStatic, hash[:])
	if err != nil {
		return nil, fmt.Errorf("wgprobetest: initiator static failed to open: %w", err)
	}
	hash = wgprobe.Hash(hash[:], encStatic)

	// ss = DH(s_r, s_i): decrypt (validate) the timestamp.
	ss, err := curve25519.X25519(r.staticPriv[:], initStaticPub)
	if err != nil {
		return nil, err
	}
	d = wgprobe.KDF(chainKey[:], ss[:], 2)
	chainKey = d[0]
	if _, err := wgprobe.AEADOpen(d[1], encTimestamp, hash[:]); err != nil {
		return nil, fmt.Errorf("wgprobetest: timestamp failed to open: %w", err)
	}
	hash = wgprobe.Hash(hash[:], encTimestamp)

	// Response: fresh ephemeral, ee/se/psk with tau in the transcript.
	var ephRPriv [32]byte
	if _, err := rand.Read(ephRPriv[:]); err != nil {
		return nil, err
	}
	ephRPriv[0] &= 248
	ephRPriv[31] &= 127
	ephRPriv[31] |= 64
	ephRPub, err := curve25519.X25519(ephRPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	hash = wgprobe.Hash(hash[:], ephRPub)
	chainKey = wgprobe.KDF(chainKey[:], ephRPub, 1)[0]

	ee, err := curve25519.X25519(ephRPriv[:], ephI[:])
	if err != nil {
		return nil, err
	}
	chainKey = wgprobe.KDF(chainKey[:], ee[:], 1)[0]

	se, err := curve25519.X25519(ephRPriv[:], initStaticPub)
	if err != nil {
		return nil, err
	}
	chainKey = wgprobe.KDF(chainKey[:], se[:], 1)[0]

	// psk2 (zero for both Proton and cf-warp).
	var zeroPSK [32]byte
	d = wgprobe.KDF(chainKey[:], zeroPSK[:], 3)
	tau, key := d[1], d[2]
	hash = wgprobe.Hash(hash[:], tau[:])

	encEmpty, err := wgprobe.AEADSeal(key, nil, hash[:])
	if err != nil {
		return nil, err
	}

	head := make([]byte, 0, 76)
	head = binary.LittleEndian.AppendUint32(head, wgprobe.MessageResponseType)
	head = binary.LittleEndian.AppendUint32(head, senderIndex)
	head = binary.LittleEndian.AppendUint32(head, binary.LittleEndian.Uint32(init[4:8]))
	head = append(head, ephRPub...)
	head = append(head, encEmpty...)
	// mac1: computed against the initiator's static (the reader of it).
	m1Key := wgprobe.Hash([]byte("mac1----"), initStaticPub)
	m1 := wgprobe.KeyedBlake2s128(m1Key, head)
	out := append([]byte(nil), head...)
	out = append(out, m1...)
	out = append(out, make([]byte, 16)...) // mac2 zero
	return out, nil
}
