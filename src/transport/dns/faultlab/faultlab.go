// Package faultlab provides controlled DNS fault fixtures for the ADNS
// integration matrix (addendum §95). Fixtures prove correctness and failure
// handling; they never replace real Keenetic/Android target evidence.
package faultlab

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// Mode is a controlled fault mode.
type Mode string

const (
	ModeValid            Mode = "valid"              // valid resolver
	ModeEarlyInjection   Mode = "early_injection"    // forged early response + later valid
	ModeUDPDrop          Mode = "udp_drop"           // UDP silence
	ModeTruncation       Mode = "truncation"         // UDP TC=1, TCP complete
	ModeFakeNXDOMAIN     Mode = "fake_nxdomain"      // positive name → NXDOMAIN
	ModeStubIP           Mode = "stub_ip"            // block-page/stub IP answer
	ModeCNAMEAltered     Mode = "cname_altered"      // altered CNAME chain
	ModeAAAAOnly         Mode = "aaaa_only"          // only AAAA answers
	ModeDNSSECInvalid    Mode = "dnssec_invalid"     // bogus DNSSEC fixture
	ModeDuplicate        Mode = "duplicate"          // two identical valid responses
)

// Fixture is one controlled DNS server instance.
type Fixture struct {
	Mode Mode
	IP   net.IP // answer A record
	AAAA net.IP

	mu   sync.Mutex
	udp  *net.UDPConn
	tcp  net.Listener
	done chan struct{}
}

// StartUDP launches a UDP fixture on loopback and returns its address.
func StartUDP(mode Mode) (*Fixture, string, error) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, "", err
	}
	f := &Fixture{Mode: mode, IP: net.ParseIP("93.184.216.34"), AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"), done: make(chan struct{})}
	f.udp = conn
	go f.serveUDP()
	return f, conn.LocalAddr().String(), nil
}

// StartTCP launches a TCP fixture on loopback.
func StartTCP(mode Mode) (*Fixture, string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	f := &Fixture{Mode: mode, IP: net.ParseIP("93.184.216.34"), AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"), done: make(chan struct{})}
	f.tcp = l
	go f.serveTCP()
	return f, l.Addr().String(), nil
}

// Close stops the fixture.
func (f *Fixture) Close() {
	close(f.done)
	if f.udp != nil {
		f.udp.Close()
	}
	if f.tcp != nil {
		f.tcp.Close()
	}
}

func (f *Fixture) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, src, err := f.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		switch f.Mode {
		case ModeUDPDrop:
			continue
		case ModeEarlyInjection:
			forged := f.answer(query, net.ParseIP("10.10.10.10"), nil, 0)
			f.udp.WriteToUDP(forged, src)
			time.Sleep(50 * time.Millisecond)
			f.udp.WriteToUDP(f.answer(query, f.IP, f.AAAA, 0), src)
		case ModeDuplicate:
			resp := f.answer(query, f.IP, f.AAAA, 0)
			f.udp.WriteToUDP(resp, src)
			f.udp.WriteToUDP(resp, src)
		case ModeTruncation:
			f.udp.WriteToUDP(f.answer(query, f.IP, f.AAAA, 0x0200), src) // TC=1
		default:
			f.udp.WriteToUDP(f.answer(query, f.IP, f.AAAA, 0), src)
		}
	}
}

func (f *Fixture) serveTCP() {
	for {
		conn, err := f.tcp.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			var lenBuf [2]byte
			if _, err := readFull(c, lenBuf[:]); err != nil {
				return
			}
			query := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
			if _, err := readFull(c, query); err != nil {
				return
			}
			resp := f.answer(query, f.IP, f.AAAA, 0)
			frame := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(resp)))
			copy(frame[2:], resp)
			c.Write(frame)
		}(conn)
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// answer builds a DNS response according to the fixture mode.
func (f *Fixture) answer(query []byte, ip, aaaa net.IP, flags uint16) []byte {
	if len(query) < 12 {
		return nil
	}
	qdCount := binary.BigEndian.Uint16(query[4:6])
	// find end of question section
	off := 12
	for i := 0; i < int(qdCount); i++ {
		for off < len(query) && query[off] != 0 {
			off += 1 + int(query[off])
		}
		off += 5 // null + qtype + qclass
	}
	question := query[12:off]
	qtype := uint16(1)
	if off >= 4 {
		qtype = binary.BigEndian.Uint16(query[off-4 : off-2])
	}
	name := extractName(query)

	resp := make([]byte, 12)
	copy(resp[0:2], query[0:2])
	binary.BigEndian.PutUint16(resp[2:4], 0x8000|0x0100|0x0080|flags)
	binary.BigEndian.PutUint16(resp[4:6], qdCount)

	var answers []byte
	rcode := uint16(0)
	switch f.Mode {
	case ModeFakeNXDOMAIN:
		rcode = 3
	case ModeStubIP:
		ip = net.ParseIP("198.18.0.1")
	}
	if rcode == 0 {
		switch qtype {
		case 1: // A
			if f.Mode == ModeAAAAOnly {
				break
			}
			answers = append(answers, aRecord(question, ip)...)
		case 28: // AAAA
			answers = append(answers, aaaaRecord(question, aaaa)...)
		case 5: // CNAME
			target := "cdn.example.com"
			if f.Mode == ModeCNAMEAltered {
				target = "evil.example.net"
			}
			answers = append(answers, cnameRecord(question, name, target)...)
		}
	}
	anCount := uint16(0)
	if len(answers) > 0 {
		anCount = 1
	}
	binary.BigEndian.PutUint16(resp[6:8], anCount)
	binary.BigEndian.PutUint16(resp[2:4], binary.BigEndian.Uint16(resp[2:4])|rcode)
	resp = append(resp, question...)
	resp = append(resp, answers...)
	return resp
}

func extractName(query []byte) string {
	off := 12
	name := ""
	for off < len(query) && query[off] != 0 {
		l := int(query[off])
		off++
		if off+l > len(query) {
			break
		}
		if name != "" {
			name += "."
		}
		name += string(query[off : off+l])
		off += l
	}
	return name
}

// namePtr returns a compression pointer to the question name at offset 12.
func namePtr() []byte { return []byte{0xc0, 0x0c} }

func aRecord(question []byte, ip net.IP) []byte {
	if ip == nil {
		ip = net.ParseIP("93.184.216.34")
	}
	r := namePtr()
	r = append(r, 0, 1, 0, 1) // type A class IN
	r = append(r, 0, 0, 0, 60) // TTL
	r = append(r, 0, 4)
	return append(r, ip.To4()...)
}

func aaaaRecord(question []byte, ip net.IP) []byte {
	if ip == nil {
		ip = net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")
	}
	r := namePtr()
	r = append(r, 0, 28, 0, 1)
	r = append(r, 0, 0, 0, 60)
	r = append(r, 0, 16)
	return append(r, ip.To16()...)
}

func cnameRecord(question []byte, name, target string) []byte {
	r := namePtr()
	r = append(r, 0, 5, 0, 1)
	r = append(r, 0, 0, 0, 60)
	var enc []byte
	for _, label := range splitLabels(target) {
		enc = append(enc, byte(len(label)))
		enc = append(enc, label...)
	}
	enc = append(enc, 0)
	r = append(r, byte(len(enc)>>8), byte(len(enc)))
	return append(r, enc...)
}

func splitLabels(name string) []string {
	var out []string
	cur := ""
	for _, c := range name {
		if c == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// --- DoT / DoH fixtures ---

// TLSFixtureCert generates a self-signed server certificate for lab use.
func TLSFixtureCert(names ...string) (tls.Certificate, *x509.CertPool, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pool := x509.NewCertPool()
	pool.AddCert(&tmpl)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool = x509.NewCertPool()
	pool.AddCert(parsed)
	return cert, pool, nil
}

// StartDoT launches a DoT fixture. If corruptTLS is set the certificate is
// valid for a different hostname (certificate failure fixture, §95).
func StartDoT(mode Mode, serverName string, wrongName bool) (*Fixture, string, *x509.CertPool, error) {
	certName := serverName
	if wrongName {
		certName = "wrong.example.invalid"
	}
	cert, pool, err := TLSFixtureCert(certName)
	if err != nil {
		return nil, "", nil, err
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return nil, "", nil, err
	}
	f := &Fixture{Mode: mode, IP: net.ParseIP("93.184.216.34"), AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"), done: make(chan struct{})}
	f.tcp = l
	go f.serveTCP()
	return f, l.Addr().String(), pool, nil
}

// StartDoH launches an HTTP(S) DoH fixture. If corruptBody is set the
// fixture returns a corrupted DNS body (§95).
func StartDoH(mode Mode, corruptBody bool) (*Fixture, string, error) {
	inner, _, err := StartUDP(mode)
	if err != nil {
		return nil, "", err
	}
	_ = inner
	f := &Fixture{Mode: mode, IP: net.ParseIP("93.184.216.34"), AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"), done: make(chan struct{})}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		readFullReader(r, body)
		resp := f.answer(body, f.IP, f.AAAA, 0)
		if corruptBody {
			if len(resp) > 8 {
				resp = resp[:len(resp)/2]
			}
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	}))
	go func() {
		<-f.done
		srv.Close()
	}()
	return f, srv.URL, nil
}

func readFullReader(r *http.Request, buf []byte) {
	total := 0
	for total < len(buf) {
		n, err := r.Body.Read(buf[total:])
		total += n
		if err != nil {
			return
		}
	}
}

// PortOf extracts the port from a host:port address.
func PortOf(addr string) int {
	var port int
	fmt.Sscanf(addr, "127.0.0.1:%d", &port)
	return port
}

// WaitUDP is a helper for tests: runs fn with a context timeout.
func WaitUDP(ctx context.Context, d time.Duration, fn func(context.Context)) {
	c, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	fn(c)
}
