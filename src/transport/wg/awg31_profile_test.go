package transportwg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestDecodeProfileEntryFullAWG31ToIPC(t *testing.T) {
	hp := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	raw := json.RawMessage(`{
		"id":"awg31-full",
		"target":"awg-server",
		"jc":6,"jmin":10,"jmax":50,
		"s1":43,"s2":143,"s3":21,"s4":12,
		"h1":[1,1],"h2":[2,2],"h3":[3,3],"h4":[4,4],
		"header_protection_key":"` + hp + `",
		"content_padding_addition":[10,100],
		"rekey_after_time":[100,120],
		"rekey_timeout":[3,7],
		"reject_after_time":[150,180],
		"keepalive_timeout":[5,15],
		"max_handshake_attempts":[15,20],
		"random_trailers":true,
		"disable_cookies":true
	}`)

	tpl, err := decodeProfileEntry(raw)
	if err != nil {
		t.Fatalf("decodeProfileEntry: %v", err)
	}
	p, err := tpl.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PrivateKey: priv,
		Profile:    p,
		Peers: []PeerConfig{{
			PublicKey:  peer,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	}
	uapi, err := cfg.IPCString()
	if err != nil {
		t.Fatalf("IPCString: %v", err)
	}
	for _, want := range []string{
		"jc=6", "jmin=10", "jmax=50",
		"s1=43", "s2=143", "s3=21", "s4=12",
		"h1=1", "h2=2", "h3=3", "h4=4",
		"header_protection_key=" + strings.Repeat("42", 32),
		"content_padding_addition=10-100",
		"rekey_after_time=100-120",
		"rekey_timeout=3-7",
		"reject_after_time=150-180",
		"keepalive_timeout=5-15",
		"max_handshake_attempts=15-20",
		"random_trailers=true",
		"disable_cookies=true",
	} {
		if !strings.Contains(uapi, want+"\n") {
			t.Fatalf("missing %q in UAPI:\n%s", want, uapi)
		}
	}
}

func TestDecodeProfileEntryRejectsBadAWG31HeaderKey(t *testing.T) {
	for _, raw := range []string{
		`{"id":"bad-hp-encoding","target":"awg-server","header_protection_key":"%%%"}`,
		`{"id":"bad-hp-length","target":"awg-server","header_protection_key":"YQ=="}`,
	} {
		if _, err := decodeProfileEntry(json.RawMessage(raw)); err == nil {
			t.Fatalf("invalid header protection key accepted: %s", raw)
		}
	}
}

func TestAWG31BothEndFeaturesRejectedForStockWarp(t *testing.T) {
	raw := json.RawMessage(`{
		"id":"warp-must-stay-stock-compatible",
		"target":"cf-warp",
		"content_padding_addition":[10,20]
	}`)
	_, err := decodeProfileEntry(raw)
	if err == nil {
		t.Fatal("cf-warp profile with AWG 3.1 both-end feature was accepted")
	}
	if !strings.Contains(err.Error(), "vanilla-safe") {
		t.Fatalf("wrong rejection: %v", err)
	}
}

func TestVanillaSafeRejectsAWG31WireFeatures(t *testing.T) {
	r := func(lo, hi uint32) *Range { return &Range{Lo: lo, Hi: hi} }
	cases := map[string]Profile{
		"content-padding":       {ContentPadding: r(10, 20)},
		"random-trailers":       {RandomTrailers: true},
		"disable-cookies":       {DisableCookies: true},
		"rekey-after-time":      {RekeyAfterTime: r(100, 120)},
		"rekey-timeout":         {RekeyTimeout: r(3, 7)},
		"reject-after-time":     {RejectAfterTime: r(150, 180)},
		"keepalive-timeout":     {KeepaliveTimeout: r(5, 15)},
		"max-handshake-attempts": {MaxHandshakeAtt: r(15, 20)},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if p.VanillaSafe() {
				t.Fatalf("%s unexpectedly classified vanilla-safe", name)
			}
		})
	}

	clientOnly := Profile{JunkCount: 4, JunkMin: 40, JunkMax: 70, InitPacket: [5]string{"<b 0xce00>"}}
	if !clientOnly.VanillaSafe() {
		t.Fatal("client-side J/I camouflage must remain vanilla-safe")
	}
}
