package transportwg

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func wgStackTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestWGStackCarriesLargeTLS pins the field finding of bd b4x-q03/b4x-nxx:
// the SAME engine wiring a field session uses (amneziawg device + our Bind +
// gVisor netstack on BOTH ends) carries a 20 KB TLS transfer over a loopback
// UDP pair. The field stall is therefore NOT in this stack (gVisor/netstack/
// Bind/config); it is the outer WARP flow going silent. Regression guard.
func TestWGStackCarriesLargeTLS(t *testing.T) {
	privA, privB, pubA, pubB := mustKeys(t)

	// ---- server side ----
	sBind := NewBind(SocketOptions{})
	sTun, sNet, err := netstack.CreateNetTUN([]netip.Addr{ip4([4]byte{10, 0, 0, 1})}, nil, DefaultMTU)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	sDev := device.NewDevice(sTun, sBind, DeviceLogger(nil))
	defer sDev.Close()
	sIPC, err := (&Config{
		PrivateKey: privB,
		Peers: []PeerConfig{{
			PublicKey:  pubA,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
		}},
	}).IPCString()
	if err != nil {
		t.Fatal(err)
	}
	if err := sDev.IpcSet(sIPC); err != nil {
		t.Fatalf("server IpcSet: %v", err)
	}
	if err := sDev.Up(); err != nil {
		t.Fatalf("server Up: %v", err)
	}
	sPort := sBind.ActualPort()
	if sPort == 0 {
		t.Fatal("server bind no port")
	}

	// ---- client side ----
	cBind := NewBind(SocketOptions{})
	cTun, cNet, err := netstack.CreateNetTUN([]netip.Addr{ip4([4]byte{10, 0, 0, 2})}, nil, DefaultMTU)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	cDev := device.NewDevice(cTun, cBind, DeviceLogger(nil))
	defer cDev.Close()
	cIPC, err := (&Config{
		PrivateKey: privA,
		Peers: []PeerConfig{{
			PublicKey:  pubB,
			Endpoint:   mustAddrPort("127.0.0.1:" + itoaPort(sPort)),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		}},
	}).IPCString()
	if err != nil {
		t.Fatal(err)
	}
	if err := cDev.IpcSet(cIPC); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := cDev.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	// ---- TLS server behind the server netstack ----
	cert := wgStackTestCert(t)
	ln, err := sNet.ListenTCPAddrPort(netip.MustParseAddrPort("10.0.0.1:8443"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	big := bytes.Repeat([]byte("A"), 20000)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			t.Logf("accept: %v", aerr)
			return
		}
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if herr := tc.Handshake(); herr != nil {
			t.Logf("server handshake: %v", herr)
			return
		}
		if _, werr := tc.Write(big); werr != nil {
			t.Logf("server write: %v", werr)
		}
		_ = tc.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := cNet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.0.0.1:8443"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "test"})
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	got, err := io.ReadAll(tc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(big) {
		t.Fatalf("payload len=%d want %d", len(got), len(big))
	}
}
