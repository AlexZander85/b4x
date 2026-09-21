package providers

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

func TestTLSCutErrorShapes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"eof", io.EOF, true},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"conn reset", syscall.ECONNRESET, true},
		{"broken pipe", syscall.EPIPE, true},
		{"wrapped eof", fmt.Errorf("read tcp: %w", io.EOF), true},
		{"string unexpected EOF", fmt.Errorf("tls: unexpected EOF while reading"), true},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := tlsCutError(tc.err); got != tc.want {
			t.Fatalf("%s: tlsCutError=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestDoTProbeEOFIsMidHandshake proves the field signature: a peer that accepts
// the TCP connection, reads the ClientHello and then closes (FIN, zero bytes of
// the next record) must be classified TLS_MID_HANDSHAKE_RESET — not
// INCONCLUSIVE — so the family is quarantined by the recurrence tracker.
func TestDoTProbeEOFIsMidHandshake(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf) // consume ClientHello
		_ = conn.Close()      // clean FIN, no record follows
	}()
	_, portText, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)

	p := NewDoTProvider("dns.test.invalid", []net.IP{net.ParseIP("127.0.0.1")}, port, 0, "catalog-test")
	prep, err := p.Prepare(context.Background(), dnspath.DNSPrepareRequest{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Probe(context.Background(), prep, dnspath.DNSProbeQuery{
		Name: "example.com", QType: 1, SuiteCase: "A", Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class != dnspath.OutcomeTLSMidHandshakeReset {
		t.Fatalf("class = %s, want %s (attribution=%q)", out.Class, dnspath.OutcomeTLSMidHandshakeReset, out.Attribution)
	}
	if out.Stage != dnspath.StageTLS {
		t.Fatalf("stage = %s, want %s", out.Stage, dnspath.StageTLS)
	}
}
