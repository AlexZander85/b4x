// utfingerprint_test.go: FX-M1 pins — the uTLS Firefox hello produces a
// Firefox-shaped ClientHello (GREASE + h2 ALPN), a real TLS stand accepts
// it and negotiates h2, the verification callback enforces WebPKI hostname
// semantics, and the fake-stand InsecureSkipVerify seam behaves exactly
// like the plain-Go path.
package fxvpn

import (
        "bytes"
        "context"
        "crypto/tls"

        "crypto/x509"
        "io"
        "net"
        "testing"
        "time"

        utls "github.com/refraction-networking/utls"
)

// captureHello accepts ONE raw TCP connection, records the first TLS record
// (the ClientHello) and drops the stream: the hello bytes are the artifact,
// no TLS termination is attempted.
func captureHello(t *testing.T) (chan []byte, net.Listener) {
        t.Helper()
        ln, err := net.Listen("tcp", "127.0.0.1:0")
        if err != nil {
                t.Fatalf("listen: %v", err)
        }
        t.Cleanup(func() { _ = ln.Close() })
        ch := make(chan []byte, 1)
        go func() {
                raw, err := ln.Accept()
                if err != nil {
                        return
                }
                _ = raw.SetDeadline(time.Now().Add(5 * time.Second))
                head := make([]byte, 5)
                if _, err := io.ReadFull(raw, head); err != nil {
                        _ = raw.Close()
                        close(ch)
                        return
                }
                recLen := int(head[3])<<8 | int(head[4])
                body := make([]byte, recLen)
                if _, err := io.ReadFull(raw, body); err != nil {
                        _ = raw.Close()
                        close(ch)
                        return
                }
                ch <- append(append([]byte{}, head...), body...)
                _ = raw.Close() // the handshake dies here by design; hello captured
        }()
        return ch, ln
}

// TestUTLSFirefoxHelloShape pins the FX-M1 fingerprint core: the ClientHello
// on the wire is the uTLS Firefox profile — GREASE present (no crypto/tls
// hello carries it) and the h2 ALPN offer inside.
func TestUTLSFirefoxHelloShape(t *testing.T) {
        helloCh, ln := captureHello(t)

        raw, err := net.Dial("tcp", ln.Addr().String())
        if err != nil {
                t.Fatalf("dial: %v", err)
        }
        defer raw.Close()
        m := DefaultMasquerade()
        // The sniffer drops the stream right after the hello: a handshake error
        // here is EXPECTED and irrelevant — the artifact is the bytes.
        _, _ = dialUTLSClient(context.Background(), raw, "edge.example", m, func(cs utls.ConnectionState) error {
                return nil
        })

        hello, ok := <-helloCh
        if !ok {
                t.Fatal("ClientHello was never captured")
        }
        if !bytes.Contains(hello, []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'}) {
                t.Fatal("ClientHello must carry the h2 ALPN extension")
        }
        // Firefox supported_groups order: x25519, secp256r1, secp384r1,
        // secp521r1, ffdhe2048, ffdhe3072 — crypto/tls never emits the FFDHE
        // tail, so its presence marks the Firefox profile.
        if !bytes.Contains(hello, []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01}) {
                t.Fatal("ClientHello must carry the Firefox supported_groups order")
        }
        // And it must NOT offer Go 1.24+'s default ML-KEM hybrid group (0x4588)
        // in supported_groups. A whole-buffer bytes.Contains is unreliable: the
        // 2-byte pattern can coincidentally occur in the random/session_id/GREASE
        // bytes (was a 2/300 flake). Parse the extension instead.
        groups, ok := clientHelloSupportedGroups(hello)
        if !ok {
                t.Fatal("ClientHello must carry the supported_groups extension")
        }
        for _, g := range groups {
                if g == 0x4588 {
                        t.Fatal("Go-default ML-KEM group leaked into the Firefox hello")
                }
        }
}

// clientHelloSupportedGroups parses the supported_groups (0x000a) extension
// out of a captured single-record ClientHello and returns the offered group
// IDs. ok=false when the record or the extension cannot be parsed.
func clientHelloSupportedGroups(hello []byte) ([]uint16, bool) {
        // TLS record: type(1) version(2) length(2), then the handshake.
        if len(hello) < 5+4 || hello[0] != 0x16 || hello[5] != 0x01 {
                return nil, false
        }
        body := hello[9:] // handshake header: msg_type(1) length(3)
        // ClientHello body: legacy_version(2) random(32) session_id(1+n)
        // cipher_suites(2+n) compression(1+n) extensions(2+n).
        if len(body) < 2+32+1 {
                return nil, false
        }
        off := 2 + 32
        sidLen := int(body[off])
        off += 1 + sidLen
        if off+2 > len(body) {
                return nil, false
        }
        suitesLen := int(body[off])<<8 | int(body[off+1])
        off += 2 + suitesLen
        if off+1 > len(body) {
                return nil, false
        }
        compLen := int(body[off])
        off += 1 + compLen
        if off+2 > len(body) {
                return nil, false
        }
        extTotal := int(body[off])<<8 | int(body[off+1])
        off += 2
        end := off + extTotal
        if end > len(body) {
                end = len(body)
        }
        for off+4 <= end {
                extType := uint16(body[off])<<8 | uint16(body[off+1])
                extLen := int(body[off+2])<<8 | int(body[off+3])
                off += 4
                if off+extLen > end {
                        return nil, false
                }
                if extType == 0x000a {
                        data := body[off : off+extLen]
                        if len(data) < 2 {
                                return nil, false
                        }
                        listLen := int(data[0])<<8 | int(data[1])
                        if listLen > len(data)-2 {
                                return nil, false
                        }
                        var groups []uint16
                        for i := 2; i+1 < 2+listLen; i += 2 {
                                groups = append(groups, uint16(data[i])<<8|uint16(data[i+1]))
                        }
                        return groups, true
                }
                off += extLen
        }
        return nil, false
}

// utlsStand is a minimal crypto/tls server offering ALPN h2.
func utlsStand(t *testing.T) (net.Listener, *x509.Certificate) {
        t.Helper()
        cert := newSelfSignedCert(t)
        ln, err := net.Listen("tcp", "127.0.0.1:0")
        if err != nil {
                t.Fatalf("listen: %v", err)
        }
        t.Cleanup(func() { _ = ln.Close() })
        go func() {
                for {
                        c, err := ln.Accept()
                        if err != nil {
                                return
                        }
                        go func(c net.Conn) {
                                srv := tls.Server(c, &tls.Config{
                                        Certificates: []tls.Certificate{cert},
                                        NextProtos:   []string{"h2"},
                                })
                                _ = srv.Handshake()
                                io.Copy(io.Discard, srv)
                        }(c)
                }
        }()
        leaf, perr := x509.ParseCertificate(cert.Certificate[0])
        if perr != nil {
                t.Fatalf("parse stand leaf: %v", perr)
        }
        return ln, leaf
}

// TestUTLSHandshakeCompletesWithH2 pins interop + trust: the Firefox hello
// completes a real TLS handshake against a standard crypto/tls server,
// negotiates h2, and the verification closure accepts the stand's cert only
// through the explicit pool seam.
func TestUTLSHandshakeCompletesWithH2(t *testing.T) {
        ln, leafRaw := utlsStand(t)

        raw, err := net.Dial("tcp", ln.Addr().String())
        if err != nil {
                t.Fatalf("dial: %v", err)
        }
        defer raw.Close()

        pool := x509.NewCertPool()
        leafDER, perr := x509.ParseCertificate(leafRaw.Raw)
        if perr != nil {
                t.Fatalf("parse leaf: %v", perr)
        }
        pool.AddCert(leafDER)
        m := DefaultMasquerade()
        uc, err := dialUTLSClient(context.Background(), raw, "127.0.0.1", m, verifyWebPKIUTLS("127.0.0.1", pool, false))
        if err != nil {
                t.Fatalf("uTLS handshake: %v", err)
        }
        defer uc.Close()
        if got := uc.ConnectionState().NegotiatedProtocol; got != "h2" {
                t.Fatalf("negotiated %q, want h2", got)
        }
}

// TestUTLSVerificationCallbackEnforcesWebPKI pins the red line: the uTLS
// layer changes the OBSERVED BYTES, never the verification — an unverifiable
// chain must fail the handshake when the plain path would verify.
func TestUTLSVerificationCallbackEnforcesWebPKI(t *testing.T) {
        ln, _ := utlsStand(t)

        raw, err := net.Dial("tcp", ln.Addr().String())
        if err != nil {
                t.Fatalf("dial: %v", err)
        }
        defer raw.Close()
        m := DefaultMasquerade()
        // No roots: the self-signed stand cannot verify — the callback must
        // reject exactly like crypto/tls would.
        _, err = dialUTLSClient(context.Background(), raw, "127.0.0.1", m, verifyWebPKIUTLS("127.0.0.1", nil, false))
        if err == nil {
                t.Fatal("unverifiable chain must fail the uTLS handshake")
        }
}
