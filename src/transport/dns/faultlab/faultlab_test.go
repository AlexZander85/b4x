package faultlab

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// These tests are validation-of-validation (§100): each fixture mode must
// provably exhibit the fault it claims to model. They never replace real
// target evidence (ADNS-15).

func buildQuery(id uint16, name string, qtype uint16) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], id)
	binary.BigEndian.PutUint16(q[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(q[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1)
	return append(q, tail[:]...)
}

func udpQuery(t *testing.T, addr string, q []byte, replies int) [][]byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(q); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out [][]byte
	buf := make([]byte, 4096)
	for len(out) < replies {
		conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			return out
		}
		resp := make([]byte, n)
		copy(resp, buf[:n])
		out = append(out, resp)
	}
	return out
}

func rcode(resp []byte) uint16 { return binary.BigEndian.Uint16(resp[2:4]) & 0x000f }
func ancount(resp []byte) int  { return int(binary.BigEndian.Uint16(resp[6:8])) }
func tcBit(resp []byte) bool   { return binary.BigEndian.Uint16(resp[2:4])&0x0200 != 0 }

func answerA(resp []byte) net.IP {
	if ancount(resp) == 0 {
		return nil
	}
	// header(12) + question + answer header with compression pointer
	off := 12
	for resp[off] != 0 {
		off += 1 + int(resp[off])
	}
	off += 5 // null + qtype + qclass
	// answer: ptr(2) type(2) class(2) ttl(4) rdlen(2)
	return net.IP(resp[off+12 : off+16])
}

func TestFixtureValidAnswersA(t *testing.T) {
	fx, addr, err := StartUDP(ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	resps := udpQuery(t, addr, buildQuery(1, "example.com", 1), 1)
	if len(resps) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resps))
	}
	if rcode(resps[0]) != 0 || ancount(resps[0]) != 1 {
		t.Fatalf("invalid fixture answer: rcode=%d an=%d", rcode(resps[0]), ancount(resps[0]))
	}
	if got := answerA(resps[0]); !got.Equal(fx.IP) {
		t.Fatalf("fixture returned %v, want %v", got, fx.IP)
	}
}

func TestFixtureEarlyInjectionSendsForgedFirst(t *testing.T) {
	fx, addr, err := StartUDP(ModeEarlyInjection)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	resps := udpQuery(t, addr, buildQuery(2, "example.com", 1), 2)
	if len(resps) != 2 {
		t.Fatalf("expected forged+valid pair, got %d responses", len(resps))
	}
	if forged := answerA(resps[0]); !forged.Equal(net.ParseIP("10.10.10.10")) {
		t.Fatalf("first response must be forged stub, got %v", forged)
	}
	if valid := answerA(resps[1]); !valid.Equal(fx.IP) {
		t.Fatalf("second response must be valid, got %v", valid)
	}
}

func TestFixtureUDPDropIsSilent(t *testing.T) {
	fx, addr, err := StartUDP(ModeUDPDrop)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	if resps := udpQuery(t, addr, buildQuery(3, "example.com", 1), 1); len(resps) != 0 {
		t.Fatalf("drop fixture answered %d times", len(resps))
	}
}

func TestFixtureTruncationSetsTC(t *testing.T) {
	fx, addr, err := StartUDP(ModeTruncation)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	resps := udpQuery(t, addr, buildQuery(4, "example.com", 1), 1)
	if len(resps) != 1 || !tcBit(resps[0]) {
		t.Fatalf("truncation fixture must set TC, resps=%d", len(resps))
	}
}

func TestFixtureFakeNXDOMAIN(t *testing.T) {
	fx, addr, err := StartUDP(ModeFakeNXDOMAIN)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	resps := udpQuery(t, addr, buildQuery(5, "positive.example.com", 1), 1)
	if len(resps) != 1 || rcode(resps[0]) != 3 {
		t.Fatalf("expected NXDOMAIN, resps=%d rcode=%d", len(resps), rcode(resps[0]))
	}
}

func TestFixtureStubIP(t *testing.T) {
	fx, addr, err := StartUDP(ModeStubIP)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	resps := udpQuery(t, addr, buildQuery(6, "blocked.example", 1), 1)
	if len(resps) != 1 {
		t.Fatal("no response")
	}
	if got := answerA(resps[0]); !got.Equal(net.ParseIP("198.18.0.1")) {
		t.Fatalf("stub fixture returned %v, want 198.18.0.1", got)
	}
}

func TestFixtureCNAMEAltered(t *testing.T) {
	fx, addr, err := StartUDP(ModeCNAMEAltered)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	resps := udpQuery(t, addr, buildQuery(7, "www.example.com", 5), 1)
	if len(resps) != 1 {
		t.Fatal("no response")
	}
	body := string(resps[0])
	// CNAME labels are length-prefixed on the wire, so match per-label.
	for _, label := range []string{"evil", "example", "net"} {
		if !strings.Contains(body, label) {
			t.Fatalf("altered fixture must point CNAME to evil.example.net, missing label %q", label)
		}
	}
}

func TestFixtureAAAAOnly(t *testing.T) {
	fx, addr, err := StartUDP(ModeAAAAOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	resps := udpQuery(t, addr, buildQuery(8, "example.com", 1), 1)
	if len(resps) != 1 || ancount(resps[0]) != 0 {
		t.Fatal("AAAA-only fixture must not answer A queries")
	}
	resps = udpQuery(t, addr, buildQuery(9, "example.com", 28), 1)
	if len(resps) != 1 || ancount(resps[0]) != 1 {
		t.Fatal("AAAA-only fixture must answer AAAA queries")
	}
}

func TestFixtureDuplicate(t *testing.T) {
	fx, addr, err := StartUDP(ModeDuplicate)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	resps := udpQuery(t, addr, buildQuery(10, "example.com", 1), 2)
	if len(resps) != 2 {
		t.Fatalf("duplicate fixture must send 2 identical responses, got %d", len(resps))
	}
	if string(resps[0]) != string(resps[1]) {
		t.Fatal("duplicate responses must be identical")
	}
}

func TestFixtureTCPFramedAnswer(t *testing.T) {
	fx, addr, err := StartTCP(ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := buildQuery(11, "example.com", 1)
	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
	copy(frame[2:], q)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	var lenBuf [2]byte
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if rcode(resp) != 0 || ancount(resp) != 1 {
		t.Fatal("TCP fixture must return a valid framed answer")
	}
}

func TestFixtureDoTWrongCertificateRejected(t *testing.T) {
	// Wrong-name fixture: certificate valid for a different hostname must
	// fail verification against the requested server name (§95).
	fx, _, pool, err := StartDoT(ModeValid, "dns.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	conn, err := tls.Dial("tcp", fx.tcp.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: "dns.example.com",
	})
	if err == nil {
		conn.Close()
		t.Fatal("wrong-name certificate must be rejected")
	}

	fx2, _, pool2, err := StartDoT(ModeValid, "dns.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	defer fx2.Close()
	conn, err = tls.Dial("tcp", fx2.tcp.Addr().String(), &tls.Config{
		RootCAs:    pool2,
		ServerName: "dns.example.com",
	})
	if err != nil {
		t.Fatalf("correct-name certificate must verify: %v", err)
	}
	conn.Close()
}

func TestFixtureDoHCorruptBody(t *testing.T) {
	fx, url, err := StartDoH(ModeValid, true)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	// TLS of httptest.NewTLSServer is self-signed; use an insecure client
	// inside the lab only.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	q := buildQuery(12, "example.com", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url+"/dns-query", strings.NewReader(string(q)))
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(body) < 12 {
		t.Fatalf("corrupt fixture returned %d bytes", len(body))
	}
	if ancount(body) != 1 {
		t.Fatal("corrupt fixture must truncate the DNS body")
	}
	// sanity: uncorrupted variant answers with exactly one A record
	fx2, url2, err := StartDoH(ModeValid, false)
	if err != nil {
		t.Fatal(err)
	}
	defer fx2.Close()
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, url2+"/dns-query", strings.NewReader(string(q)))
	req2.Header.Set("Content-Type", "application/dns-message")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if ancount(body2) != 1 || answerA(body2) == nil {
		t.Fatal("uncorrupted DoH fixture must return a parseable A answer")
	}
}
