package vless

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVisionInteropXray runs the in-process VLESS client against a REAL
// Xray-core server configured with flow=xtls-rprx-vision, over plain TLS.
// It is the mandatory interop gate for b4x-7e2 and is skipped unless
// B4_XRAY_BIN points at an xray binary.
func TestVisionInteropXray(t *testing.T) {
	bin := os.Getenv("B4_XRAY_BIN")
	if bin == "" {
		t.Skip("B4_XRAY_BIN not set: skipping real-Xray Vision interop")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("xray binary %q not found: %v", bin, err)
	}
	for _, flow := range []string{"", FlowVision} {
		name := "plain"
		if flow != "" {
			name = "vision"
		}
		t.Run(name, func(t *testing.T) { runXrayInterop(t, bin, flow) })
	}
}

func runXrayInterop(t *testing.T, bin, flow string) {
	dir := t.TempDir()
	cert, pool := selfSignedCert(t, "test.local")
	writeCertPEM(t, dir, cert)

	uuid := "11111111-1111-1111-1111-111111111111"
	port := freeTCPPort(t)
	cfg := fmt.Sprintf(`{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "%s", "flow": %q}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {"certificates": [{"certificateFile": %q, "keyFile": %q}]}
    }
  }],
  "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
}`, port, uuid, flow, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	cfgPath := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "-c", cfgPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)

	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "vision-interop-ok")
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "https://")

	node := Node{
		UUID: uuid, Host: "127.0.0.1", Port: uint16(port),
		Security: SecurityTLS, SNI: "test.local", Transport: TransportTCP, Flow: flow,
	}
	d := &Dialer{Node: node, RootCAs: pool, Timeout: 15 * time.Second}
	vconn, err := d.Dial(context.Background(), netip.MustParseAddrPort(targetAddr))
	if err != nil {
		t.Fatalf("dial xray node: %v", err)
	}
	defer vconn.Close()

	// Inner TLS (TLS-in-TLS): exactly the Vision use case.
	inner := &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true}
	tr := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			return tls.Client(vconn, inner), nil
		},
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	resp, err := client.Get("https://" + targetAddr + "/")
	if err != nil {
		t.Fatalf("request through xray tunnel (flow=%q): %v", flow, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "vision-interop-ok" {
		t.Fatalf("flow=%q status=%d body=%q", flow, resp.StatusCode, body)
	}
}

func writeCertPEM(t *testing.T, dir string, cert *tls.Certificate) {
	t.Helper()
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected private key type %T", cert.PrivateKey)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("xray inbound %s not ready: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
