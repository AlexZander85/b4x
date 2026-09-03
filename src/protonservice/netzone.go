// Netzone discovery (review P6, design §1.7): the Proton API ranks server
// proximity by the X-PM-netzone header — the client's public IP masked to
// its /24. The field existed on the client but was never computed, so the
// header never went out and the server fell back to its default ranking.
//
// The probe is a minimal RFC 5389 STUN binding exchange against public
// STUN anchors, executed ONCE per boot at Start (direct egress, never the
// proton tunnel — the tunnel does not exist yet at that point). A failed
// discovery leaves the netzone empty: the header is simply not sent (the
// honest degrade), never a wrong value.
package protonservice

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/daniellavrushin/b4/transport/proton"
)

// netzoneAnchors are the STUN anchors tried in order (public, anycast,
// plain-UDP RFC 5389).
var netzoneAnchors = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun1.l.google.com:19302",
}

const (
	netzoneProbeTimeout = 5 * time.Second
	// stunMagicCookie is the RFC 5389 magic cookie.
	stunMagicCookie = 0x2112A442
)

// netzoneDialFunc is the probe transport seam (tests substitute a fake
// STUN edge; production dials UDP directly).
type netzoneDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// discoverNetzone walks the anchors and returns the public IPv4 /24 of the
// default egress ("a.b.c.0/24"), "" when every anchor failed or the mapped
// address is not IPv4 (Proton's netzone ranking is v4/24).
func discoverNetzone(ctx context.Context, dial netzoneDialFunc) string {
	if dial == nil {
		return ""
	}
	for _, anchor := range netzoneAnchors {
		pctx, cancel := context.WithTimeout(ctx, netzoneProbeTimeout)
		ip, err := stunMappedV4(pctx, dial, anchor)
		cancel()
		if err != nil {
			continue
		}
		if zone := maskV4To24(ip); zone != "" {
			return zone
		}
	}
	return ""
}

// stunMappedV4 performs one STUN binding exchange and returns the
// XOR-MAPPED-ADDRESS IPv4.
func stunMappedV4(ctx context.Context, dial netzoneDialFunc, anchor string) (net.IP, error) {
	conn, err := dial(ctx, "udp4", anchor)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(netzoneProbeTimeout))

	// Binding request: type 0x0001, length 0, magic cookie, 12-byte txn id.
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	txn := req[8:20]
	if _, err := crand.Read(txn); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		resp := buf[:n]
		if len(resp) < 20 || binary.BigEndian.Uint16(resp[0:2]) != 0x0101 {
			continue // not a binding response
		}
		if string(resp[8:20]) != string(txn) {
			continue // foreign transaction
		}
		return parseXorMappedV4(resp)
	}
}

// parseXorMappedV4 extracts the XOR-MAPPED-ADDRESS (0x0020) attribute.
func parseXorMappedV4(resp []byte) (net.IP, error) {
	if len(resp) < 20 {
		return nil, errors.New("stun: short response")
	}
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	body := resp[20:]
	if msgLen > len(body) {
		return nil, errors.New("stun: declared length overruns the datagram")
	}
	body = body[:msgLen]
	for len(body) >= 4 {
		attrType := binary.BigEndian.Uint16(body[0:2])
		attrLen := int(binary.BigEndian.Uint16(body[2:4]))
		if 4+attrLen > len(body) {
			return nil, errors.New("stun: attribute overruns the message")
		}
		if attrType == 0x0020 && attrLen >= 8 && body[4] == 0x00 && body[5] == 0x01 {
			// The mapped port is unused for the netzone (IP-only /24) —
			// kept out deliberately to avoid implying port awareness.
			ip := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				ip[i] = body[8+i] ^ byte(uint32(stunMagicCookie)>>(24-8*i))
			}
			return ip, nil
		}
		// TLV stride, 4-byte aligned per RFC 5389 §15.
		attrLen = (attrLen + 3) &^ 3
		body = body[4+attrLen:]
	}
	return nil, errors.New("stun: no XOR-MAPPED-ADDRESS attribute")
}

// maskV4To24 renders the netzone header value: the /24 of a single IPv4
// ("203.0.113.199" -> "203.0.113.0/24"). Anything else (v6, invalid,
// loopback, unspecified) yields "" — the header is omitted, never guessed.
func maskV4To24(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil || v4.IsUnspecified() || v4.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
}

// applyNetzone discovers the public /24 once per boot and stores it on the
// shared control-plane client (the X-PM-netzone header then rides every
// logicals request; api.go sends it only when non-empty). Safe to call
// concurrently; a failed discovery stays empty and emits the event.
func (r *Runtime) applyNetzone() {
	r.netzoneOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(),
			netzoneProbeTimeout*time.Duration(len(netzoneAnchors)))
		defer cancel()
		zone := discoverNetzone(ctx, func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		})
		if zone == "" {
			r.appendEvent(proton.Event{Name: "proton_netzone_unresolved",
				Detail: "no STUN anchor answered; X-PM-netzone omitted"})
			return
		}
		r.client.Netzone = zone
		r.appendEvent(proton.Event{Name: "proton_netzone_set", Detail: zone})
	})
}
