package vless

import (
	"strings"
	"testing"
)

const (
	realityURI = "vless://11111111-1111-1111-1111-111111111111@node.example.org:443" +
		"?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome" +
		"&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP&sid=0123abcd" +
		"&spx=%2F&type=tcp&flow=xtls-rprx-vision#reality-node"
	wsURI = "vless://22222222-2222-2222-2222-222222222222@203.0.113.10:8443" +
		"?security=tls&type=ws&path=%2Fws&host=cdn.example.net&sni=cdn.example.net#ws-node"
)

func TestParseURIRealityRoundTrip(t *testing.T) {
	n, err := ParseURI(realityURI)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if n.Security != SecurityReality || n.Transport != TransportTCP {
		t.Fatalf("security/transport = %q/%q", n.Security, n.Transport)
	}
	if n.Flow != FlowVision || n.PublicKey == "" || n.ShortID != "0123abcd" {
		t.Fatalf("flow/pbk/sid not parsed: %+v", n)
	}
	if n.SNI != "www.microsoft.com" || n.Fingerprint != "chrome" {
		t.Fatalf("sni/fp not parsed: %+v", n)
	}
	if n.Port != 443 || n.Name != "reality-node" {
		t.Fatalf("port/name not parsed: %+v", n)
	}
}

func TestParseURIWS(t *testing.T) {
	n, err := ParseURI(wsURI)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if n.Transport != TransportWS || n.Path != "/ws" || n.HostHeader != "cdn.example.net" {
		t.Fatalf("ws fields not parsed: %+v", n)
	}
}

func TestParseManyStats(t *testing.T) {
	lines := []string{
		realityURI,
		realityURI, // duplicate
		wsURI,
		"vmess://eyJ2IjoiMiJ9",      // other protocol
		"vless://bad@host:443",      // looks like ours, no valid shape (port ok, but no uuid? has) -> validate fails? see below
		"just-a-fragment-no-scheme", // truncated
		"",
	}
	// The 5th line: vless://bad@host:443 parses to UUID=bad, Host=host, Port=443,
	// security none -> VALID per protocol rules. Make it explicitly bad by
	// dropping the port instead.
	lines[4] = "vless://bad@host" // no port -> Validate fails

	nodes, st := ParseMany(lines)
	if st.Total != 6 {
		t.Fatalf("total=%d want 6", st.Total)
	}
	if st.VLESS != 2 {
		t.Fatalf("vless=%d want 2 (reality, ws; duplicate skipped)", st.VLESS)
	}
	if st.Duplicate != 1 {
		t.Fatalf("duplicate=%d want 1", st.Duplicate)
	}
	if st.Other != 1 || st.Truncated != 1 || st.Bad != 1 {
		t.Fatalf("other=%d truncated=%d bad=%d want 1/1/1", st.Other, st.Truncated, st.Bad)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes=%d want 2", len(nodes))
	}
}

func TestValidateDrops(t *testing.T) {
	cases := map[string]string{
		"reality without pbk": "vless://u@h.example.org:443?security=reality&sni=www.microsoft.com&type=tcp#x",
		"reality bad sni":     "vless://u@h.example.org:443?security=reality&sni=localhost&pbk=k&type=tcp#x",
		"reality ws":          "vless://u@h.example.org:443?security=reality&sni=www.microsoft.com&pbk=k&type=ws#x",
		"unknown fp":          "vless://u@h.example.org:443?security=tls&sni=www.microsoft.com&fp=nonsense#x",
		"bad flow":            "vless://u@h.example.org:443?security=tls&sni=www.microsoft.com&flow=xtls-rprx-direct#x",
		"flow without tls":    "vless://u@h.example.org:443?flow=xtls-rprx-vision&type=tcp#x",
		"empty uuid":          "vless://@h.example.org:443?type=tcp#x",
		"missing port":        "vless://u@h.example.org?type=tcp#x",
	}
	for name, uri := range cases {
		t.Run(name, func(t *testing.T) {
			n, err := ParseURI(uri)
			if err != nil {
				return // parse-level rejection is acceptable
			}
			if err := n.Validate(); err == nil {
				t.Fatalf("expected validation error for %s: %+v", name, n)
			}
		})
	}
}

func TestParseSingboxOutbound(t *testing.T) {
	doc := `{"outbounds":[{"type":"vless","tag":"sb-1","server":"203.0.113.5","server_port":443,` +
		`"uuid":"33333333-3333-3333-3333-333333333333","flow":"xtls-rprx-vision",` +
		`"tls":{"enabled":true,"server_name":"www.cloudflare.com","utls":{"enabled":true,"fingerprint":"firefox"},` +
		`"reality":{"enabled":true,"public_key":"PUBKEY","short_id":"abcd"}},` +
		`"transport":{"type":"grpc","service_name":"grpcsvc"}}]}`
	ns, err := ParseSingbox(doc)
	if err != nil {
		t.Fatalf("parse singbox: %v", err)
	}
	if len(ns) != 1 {
		t.Fatalf("nodes=%d want 1", len(ns))
	}
	n := ns[0]
	if err := n.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if n.Security != SecurityReality || n.Transport != TransportGRPC || n.ServiceName != "grpcsvc" {
		t.Fatalf("singbox fields not parsed: %+v", n)
	}
	if n.Fingerprint != "firefox" || n.PublicKey != "PUBKEY" {
		t.Fatalf("tls/reality fields not parsed: %+v", n)
	}
}

func TestPlausibleSNI(t *testing.T) {
	good := []string{"www.microsoft.com", "cdn.example.net", "a.b.co"}
	bad := []string{"", "localhost", "example.com", "test", "1.2.3.4", "nodot", "-bad.com"}
	for _, s := range good {
		if !PlausibleSNI(s) {
			t.Fatalf("PlausibleSNI(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if PlausibleSNI(s) {
			t.Fatalf("PlausibleSNI(%q) = true, want false", s)
		}
	}
}

func TestIdentityIgnoresName(t *testing.T) {
	a, _ := ParseURI(strings.Split(realityURI, "#")[0] + "#one")
	b, _ := ParseURI(strings.Split(realityURI, "#")[0] + "#two")
	if a.Identity() != b.Identity() {
		t.Fatal("identity must ignore the name label")
	}
}
