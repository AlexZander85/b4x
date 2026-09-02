// QUIC Initial forgery for the AmneziaWG I1 parameter — the Go port of Nova
// ProtonQuicInitial.kt, normalized to RFC 9000/9001.
//
// FX-M0 (E-FXVPN masquerade §7.4.1): the generator moved verbatim to the
// shared transport/quici1 package so the fxvpn preflight bait reuses it
// without a cross-domain dependency; this file keeps the proton API as a
// thin delegate. Wire behavior, grammar and constants are unchanged —
// proton/quici1_test.go still pins them.
package proton

import (
        "io"

        quici1 "github.com/daniellavrushin/b4/transport/quici1"
)

// QuicPadTo is the padded wire size of a generated Initial (RFC 9000 §14.1
// wants >=1200; real clients pad to ~1250).
const QuicPadTo = quici1.PadTo

// QuicDCIDSize is the Destination Connection ID length (8 — a 1-byte DCID
// is a tell).
const QuicDCIDSize = quici1.DCIDSize

// BuildQuicInitial assembles the fake QUIC Initial and returns it in the
// AmneziaWG `<b 0x…>` grammar. An empty/oversized SNI returns "" — the
// caller MUST treat that as "no obfuscation" (ProtonQuicInitial.kt
// buildI1 contract).
func BuildQuicInitial(sni string, r io.Reader) string { return quici1.Build(sni, r) }

// QuicInitialSize reports the wire size of an I1 value (0 when empty).
func QuicInitialSize(i1 string) int { return quici1.InitialSize(i1) }

// quicInitialSalt aliases the shared RFC 9001 §5.2 salt for the proton test
// suite's key-schedule re-derivation.
var quicInitialSalt = quici1.InitialSalt
