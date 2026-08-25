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
)

var errMalformedH3Datagram = errors.New("transportwarp: malformed h3 datagram header")

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

// AuthorityForEndpoint formats :authority for a numeric endpoint: IP:port via
// net.JoinHostPort, IPv6 literals bracketed (RFC 3986) — design §2 rule
// (:authority строго IP:port; домен краем отвергается 403, host-заголовок
// рядом с IP-authority = H3_MESSAGE_ERROR 270).
func AuthorityForEndpoint(host string, port uint16) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
