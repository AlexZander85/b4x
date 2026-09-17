// H3 DATAGRAM payload framing for MASQUE CONNECT-IP (RFC 9484 §11.2 over
// RFC 9297/9221): each QUIC datagram payload carries the quarter stream ID of
// the CONNECT stream followed by the capsule context ID, then the IP packet.
//
// Path-B note (design §3): quic-go's raw SendDatagram/ReceiveDatagram move
// bytes verbatim — unlike http3.Transport it does NOT prepend the quarter
// stream id, so this layer owns the wire format. Inbound tolerance: unknown
// context ids are skipped by the caller, not a session kill (Aether lesson).
package transportwarp

import (
	"errors"
	"fmt"
	"net"
	"os"
)

var errMalformedH3Datagram = errors.New("transportwarp: malformed h3 datagram header")

// h3DatagramOmitsCtxID reports whether the Cloudflare H3 datagram dialect
// omits the RFC 9297 context-ID. The H2 capsule path documents this as a
// non-RFC Cloudflare trait ("context-ID на проводе ОТСУТСТВУЕТ", see
// docs/reports/warp/WARP_V2_REVIEW_BRIEF.md) and works because of it; the H3
// dialect was never exercised live until the :path fix, so the field selects
// it via B4_H3_NO_CTX until a live run pins it.
func h3DatagramOmitsCtxID() bool {
	v := os.Getenv("B4_H3_NO_CTX")
	return v == "1" || v == "true"
}

// WrapH3Datagram frames one outbound packet for the given bidirectional
// CONNECT stream with capsule context id ctx (0 for CONNECT-IP).
func WrapH3Datagram(biStreamID, ctx uint64, pkt []byte) []byte {
	out := AppendVarint(nil, biStreamID/4)
	out = AppendVarint(out, ctx)
	return append(out, pkt...)
}

// UnwrapH3Datagram splits an inbound datagram into its routing fields and
// payload. It returns the QUARTER stream id as-is (callers compare against
// their own CONNECT stream's /4 form) so no multiplication ambiguity exists.
func UnwrapH3Datagram(b []byte) (quarterStreamID, ctx uint64, pkt []byte, err error) {
	qsid, n, err := ParseVarint(b)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: qsid", errMalformedH3Datagram)
	}
	ctxID, n2, err := ParseVarint(b[n:])
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: context", errMalformedH3Datagram)
	}
	pkt = b[n+n2:]
	if len(pkt) == 0 {
		return 0, 0, nil, errMalformedH3Datagram
	}
	return qsid, ctxID, pkt, nil
}

// UnwrapH3DatagramTolerant is UnwrapH3Datagram plus the Cloudflare dialect in
// which the context-ID is OMITTED (parity with the H2 capsule path). Without
// the tolerance the parser reads the first octet of the IPv4 header (0x45) as
// the context-ID, the caller discards the datagram as foreign, and the whole
// inbound path goes silent — the live "data-plane-validation-timeout" observed
// after H3 negotiation started succeeding (17.09).
func UnwrapH3DatagramTolerant(b []byte) (quarterStreamID, ctx uint64, pkt []byte, err error) {
	qsid, n, err := ParseVarint(b)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: qsid", errMalformedH3Datagram)
	}
	rest := b[n:]
	if len(rest) == 0 {
		return 0, 0, nil, errMalformedH3Datagram
	}
	// An IP header directly after the quarter stream id means the context-ID
	// was omitted (a real context-ID is a varint: 0x00 for context 0, never
	// 0x4X/0x6X).
	if v := rest[0] >> 4; v == 4 || v == 6 {
		return qsid, 0, rest, nil
	}
	ctxID, n2, err := ParseVarint(rest)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: context", errMalformedH3Datagram)
	}
	pkt = rest[n2:]
	if len(pkt) == 0 {
		return 0, 0, nil, errMalformedH3Datagram
	}
	return qsid, ctxID, pkt, nil
}

// AuthorityForEndpoint formats :authority for a numeric endpoint: IP:port via
// net.JoinHostPort, IPv6 literals bracketed (RFC 3986) — design §2 rule
// (:authority строго IP:port; домен краем отвергается 403, host-заголовок
// рядом с IP-authority = H3_MESSAGE_ERROR 270).
func AuthorityForEndpoint(host string, port uint16) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
