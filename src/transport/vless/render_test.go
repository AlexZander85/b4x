package vless

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustNode(t *testing.T, uri string) Node {
	t.Helper()
	n, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return n
}

func TestRenderXrayReality(t *testing.T) {
	n := mustNode(t, realityURI)
	out, err := Render(HelperXray, n, "127.0.0.1:1081")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("rendered json invalid: %v", err)
	}
	s := string(out)
	for _, want := range []string{`"protocol": "socks"`, `"protocol": "vless"`, `"realitySettings"`, `"publicKey"`, `"flow": "xtls-rprx-vision"`, `"port": 1081`} {
		if !strings.Contains(s, want) {
			t.Fatalf("rendered xray config missing %q:\n%s", want, s)
		}
	}
}

func TestRenderCapabilityRefusals(t *testing.T) {
	quic := Node{UUID: "u", Host: "h.example.org", Port: 443, Security: SecurityTLS, SNI: "www.microsoft.com", Transport: TransportQUIC}
	xhttp := Node{UUID: "u", Host: "h.example.org", Port: 443, Security: SecurityTLS, SNI: "www.microsoft.com", Transport: TransportXHTTP}
	kcp := Node{UUID: "u", Host: "h.example.org", Port: 443, Security: SecurityTLS, SNI: "www.microsoft.com", Transport: TransportKCP}

	if _, err := Render(HelperXray, quic, "127.0.0.1:1081"); err == nil {
		t.Fatal("xray must refuse the quic transport")
	}
	if _, err := Render(HelperSingbox, xhttp, "127.0.0.1:1081"); err == nil {
		t.Fatal("sing-box must refuse the xhttp transport")
	}
	if _, err := Render(HelperSingbox, kcp, "127.0.0.1:1081"); err == nil {
		t.Fatal("sing-box must refuse the kcp transport")
	}
	if _, err := Render(HelperSingbox, quic, "127.0.0.1:1081"); err != nil {
		t.Fatalf("sing-box must accept quic: %v", err)
	}
	if _, err := Render(HelperXray, xhttp, "127.0.0.1:1081"); err != nil {
		t.Fatalf("xray must accept xhttp: %v", err)
	}
	if _, err := Render(HelperExternal, realityNodeForTest(), "127.0.0.1:1081"); err == nil {
		t.Fatal("external helper has no rendered config")
	}
}

func realityNodeForTest() Node {
	return Node{UUID: "u", Host: "h.example.org", Port: 443, Security: SecurityReality, SNI: "www.microsoft.com", PublicKey: "k", Transport: TransportTCP}
}

func TestRenderWithUDPFlag(t *testing.T) {
	n := mustNode(t, realityURI)
	off, err := Render(HelperXray, n, "127.0.0.1:1081")
	if err != nil {
		t.Fatal(err)
	}
	on, err := RenderWithUDP(HelperXray, n, "127.0.0.1:1081", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(off), `"udp": false`) {
		t.Fatalf("default xray inbound must disable udp:\n%s", off)
	}
	if !strings.Contains(string(on), `"udp": true`) {
		t.Fatalf("udp-enabled xray inbound missing udp:true:\n%s", on)
	}
}

func TestRenderMixedInbound(t *testing.T) {
	n := mustNode(t, wsURI)
	out, err := RenderWith(HelperSingbox, n, RenderOptions{SocksAddr: "127.0.0.1:1081", Mixed: true})
	if err != nil {
		t.Fatalf("sing-box mixed: %v", err)
	}
	if !strings.Contains(string(out), `"type": "mixed"`) {
		t.Fatalf("mixed inbound missing:\n%s", out)
	}
	// Xray has no mixed protocol: it must refuse, never silently emit socks.
	if _, err := RenderWith(HelperXray, n, RenderOptions{SocksAddr: "127.0.0.1:1081", Mixed: true}); err == nil {
		t.Fatal("xray must refuse a mixed inbound")
	}
}

func TestRenderSingbox(t *testing.T) {
	n := mustNode(t, wsURI)
	out, err := Render(HelperSingbox, n, "127.0.0.1:1081")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"type": "socks"`) || !strings.Contains(s, `"type": "vless"`) {
		t.Fatalf("sing-box config missing inbounds/outbounds:\n%s", s)
	}
	if !strings.Contains(s, `"type": "ws"`) {
		t.Fatalf("sing-box config missing ws transport:\n%s", s)
	}
}

func TestNormalizeHelper(t *testing.T) {
	for in, want := range map[string]HelperKind{"": HelperXray, "xray": HelperXray, "sing-box": HelperSingbox, "singbox": HelperSingbox, "external": HelperExternal} {
		got, err := NormalizeHelper(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeHelper(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := NormalizeHelper("nope"); err == nil {
		t.Fatal("unknown helper must error")
	}
}
