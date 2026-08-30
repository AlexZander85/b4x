package transportwg

import (
	"net/netip"
	"strings"
	"testing"
)

func mustKey(t *testing.T) Key {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestIPCStringVanilla checks the minimal vanilla config renders exactly the
// keys a stock wireguard peer expects.
func TestIPCStringVanilla(t *testing.T) {
	priv := mustKey(t)
	peerPub := mustKey(t)
	cfg := Config{
		PrivateKey: priv,
		Peers: []PeerConfig{{
			PublicKey:              peerPub,
			Endpoint:               netip.MustParseAddrPort("162.159.193.10:2408"),
			AllowedIPs:             []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			PersistentKeepaliveSec: 25,
		}},
	}
	s, err := cfg.IPCString()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"private_key=" + priv.Hex(),
		"public_key=" + peerPub.Hex(),
		"endpoint=162.159.193.10:2408",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(s, want+"\n") {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

// TestIPCStringNeverRendersStoreOnlyKeys is the load-bearing invariant of the
// whitelist renderer: j1-j3/itime must never appear (research §2: one such
// key makes external awg tooling drop the WHOLE config).
func TestIPCStringNeverRendersStoreOnlyKeys(t *testing.T) {
	cfg := Config{
		PrivateKey: mustKey(t),
		Profile: Profile{
			JunkCount:       4,
			JunkMin:         40,
			JunkMax:         70,
			InitPacket:      [5]string{"<b 0xce00>"},
			HiddenJunk:      [3]string{"<b 0xdeadbeef>", "<r 5>", "<t>"},
			JunkIntervalSec: 3000,
		},
	}
	s, err := cfg.IPCString()
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"j1=", "j2=", "j3=", "itime=", "hidden"} {
		if strings.Contains(s, banned) {
			t.Fatalf("renderer leaked store-only key %q:\n%s", banned, s)
		}
	}
	for _, want := range []string{"jc=4\n", "jmin=40\n", "jmax=70\n", "i1=<b 0xce00>\n"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q:\n%s", want, s)
		}
	}
}

// TestIPCStringBoolsRenderTrueFalse pins the v3 daemon contract: random_trailers/
// disable_cookies are parsed with strconv.ParseBool upstream (uapi.go:530-544),
// so we render true/false — NOT the awg-tools "on/off" grammar.
func TestIPCStringBoolsRenderTrueFalse(t *testing.T) {
	cfg := Config{
		PrivateKey: mustKey(t),
		Profile:    Profile{RandomTrailers: true, DisableCookies: true},
	}
	s, err := cfg.IPCString()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "random_trailers=true\n") || !strings.Contains(s, "disable_cookies=true\n") {
		t.Fatalf("bool rendering wrong:\n%s", s)
	}
	if strings.Contains(s, "on") && strings.Contains(s, "=on\n") {
		t.Fatalf("awg-tools on/off grammar leaked into IPC string")
	}
}

func TestIPCStringFullAWGProfile(t *testing.T) {
	r := func(lo, hi uint32) *Range { return &Range{Lo: lo, Hi: hi} }
	cfg := Config{
		PrivateKey: mustKey(t),
		ListenPort: 0,
		FWMark:     51820,
		Profile: Profile{
			JunkCount: 5, JunkMin: 500, JunkMax: 1000,
			PadInit: 15, PadResponse: 18, PadCookie: 20, PadTransport: 25,
			HeaderInit:      r(123456, 123500),
			HeaderResponse:  r(67543, 67550),
			HeaderCookie:    r(123123, 123200),
			HeaderTransport: r(32345, 32350),
			ContentPadding:  r(16, 32),
			RekeyTimeout:    r(5, 5),
		},
		Peers: []PeerConfig{{PublicKey: mustKey(t), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}},
	}
	s, err := cfg.IPCString()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"jc=5", "jmin=500", "jmax=1000",
		"s1=15", "s2=18", "s3=20", "s4=25",
		"h1=123456-123500", "h2=67543-67550", "h3=123123-123200", "h4=32345-32350",
		"content_padding_addition=16-32",
		"rekey_timeout=5",
		"fwmark=51820",
	} {
		if !strings.Contains(s, want+"\n") {
			t.Fatalf("missing %q:\n%s", want, s)
		}
	}
}

func TestIPCStringRejectsInvalid(t *testing.T) {
	bad := Config{Peers: []PeerConfig{{PublicKey: mustKey(t)}}}
	if _, err := bad.IPCString(); err == nil {
		t.Fatalf("missing private key must fail validation")
	}

	jminOverJmax := Config{
		PrivateKey: mustKey(t),
		Profile:    Profile{JunkCount: 4, JunkMin: 900, JunkMax: 40},
	}
	if _, err := jminOverJmax.IPCString(); err == nil {
		t.Fatalf("jmin>jmax must fail before IpcSet")
	}
}

func TestParseKeyRoundTrip(t *testing.T) {
	k := mustKey(t)
	got, err := ParseKey(k.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Fatalf("key round trip mismatch")
	}
	if _, err := ParseKey("zz"); err == nil {
		t.Fatalf("bad hex accepted")
	}
	short := k.Hex()[:62]
	if _, err := ParseKey(short); err == nil {
		t.Fatalf("short key accepted")
	}
}
