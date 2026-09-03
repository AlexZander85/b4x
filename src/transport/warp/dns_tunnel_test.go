package transportwarp

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// dnsReplyFor builds a well-formed IPv4/UDP/DNS A-response from a captured
// query packet: addresses/ports reversed, QR=1, one compressed-name answer
// carrying answerIP.
func dnsReplyFor(query []byte, answerIP [4]byte) []byte {
	if len(query) < 20+8+12 {
		return nil
	}
	resp := append([]byte(nil), query...)
	copy(resp[12:16], query[16:20]) // ip src <- query dst
	copy(resp[16:20], query[12:16]) // ip dst <- query src
	copy(resp[20:22], query[22:24]) // udp sport <- query dport (53)
	copy(resp[22:24], query[20:22]) // udp dport <- query sport

	dnsLen := len(query) - 28
	body := make([]byte, 0, dnsLen+16)
	body = append(body, resp[28:]...) // header + question verbatim
	body[2] = 0x81                    // QR=1, RD kept
	body[3] = 0x80                    // RA, rcode 0
	body[6], body[7] = 0x00, 0x01     // ANCOUNT=1
	body = append(body,
		0xC0, 0x0C, // name: pointer to question qname
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3C, // TTL 60
		0x00, 0x04, // rdlength 4
	)
	body = append(body, answerIP[:]...)

	out := append(resp[:28:28], body...)
	udpLen := uint16(8 + len(body))
	binary.BigEndian.PutUint16(out[24:26], udpLen) // udp length field (ip20+off4)
	total := 20 + int(udpLen)
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	// IP checksum recompute; UDP checksum zeroed (legal over IPv4).
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], ^fold(checksum32(out[:20])))
	binary.BigEndian.PutUint16(out[26:28], 0)
	return out
}

// Happy path: a validated session carries the DNS exchange and the parser
// returns the A record.
func TestTunnelResolverResolvesA(t *testing.T) {
	h := newNestedHarness(t)
	sess := establishSession(t, h.tmpl, h.mqBase)
	defer sess.Close()

	h.mqBase.setResponder(func(q []byte) []byte { return dnsReplyFor(q, [4]byte{1, 2, 3, 4}) })

	r := NewTunnelResolver(sess, [4]byte{172, 16, 0, 2}).WithTimeout(3 * time.Second)
	addrs, rtt, err := r.LookupIP(context.Background(), "cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != netip.AddrFrom4([4]byte{1, 2, 3, 4}) {
		t.Fatalf("addrs = %v", addrs)
	}
	if rtt <= 0 {
		t.Fatalf("rtt not measured: %v", rtt)
	}
}

// Silent-drop edge: the resolver must fail with ErrDNSNoAnswer inside its
// deadline instead of blocking forever.
func TestTunnelResolverTimesOutOnSilentDrop(t *testing.T) {
	h := newNestedHarness(t)
	sess := establishSession(t, h.tmpl, h.mqBase)
	defer sess.Close()
	h.mqBase.setBehavior(200, true, false, 0) // swallow everything

	r := NewTunnelResolver(sess, [4]byte{172, 16, 0, 2}).WithTimeout(200 * time.Millisecond)
	if _, _, err := r.LookupIP(context.Background(), "cloudflare.com"); !errors.Is(err, ErrDNSNoAnswer) {
		t.Fatalf("want ErrDNSNoAnswer, got %v", err)
	}
}

// establishSession dials a validated CONNECT-IP session against a fixture.
func establishSession(t *testing.T, tmpl SessionConfig, fs *fakeServer) *Session {
	t.Helper()
	cfg := tmpl
	cfg.Endpoint = fs.addr()
	sess, res, err := DialSession(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial: %v (class %s status %d)", err, res.FailureClass, res.Status)
	}
	if err := sess.ValidateDataPlane(context.Background()); err != nil {
		sess.Close()
		t.Fatalf("validate: %v", err)
	}
	return sess
}
