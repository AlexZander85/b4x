//go:build linux

// PATCH-23 (E-WG NIT package) tests.
package transportwg

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// TestParseUint32RejectsTrailingGarbage (NIT4): Sscanf silently accepted
// "12abc"; the strict parser rejects it while tolerating whitespace.
func TestParseUint32RejectsTrailingGarbage(t *testing.T) {
	cases := []struct {
		in    string
		want  uint32
		exact bool // require the value to match exactly (success cases)
		fail  bool
	}{
		{in: "42", want: 42, exact: true},
		{in: " 42 ", want: 42, exact: true},
		{in: "4294967295", want: 4294967295, exact: true},
		{in: "12abc", fail: true},
		{in: "abc", fail: true},
		{in: "4294967296", fail: true}, // > uint32
		{in: "-1", fail: true},
	}
	for _, tc := range cases {
		got, err := parseUint32(tc.in)
		if tc.fail {
			if err == nil {
				t.Fatalf("parseUint32(%q) = %d, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseUint32(%q): %v", tc.in, err)
		}
		if tc.exact && got != tc.want {
			t.Fatalf("parseUint32(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestEmptyAllowedIPsRejected (NIT5): empty AllowedIPs is a validation
// error — the silent 0.0.0.0/0+::/0 grant is gone; the session render
// declares the default route EXPLICITLY.
func TestEmptyAllowedIPsRejected(t *testing.T) {
	cfg := Config{
		PrivateKey: mustKeyNow(),
		Peers:      []PeerConfig{{PublicKey: mustKeyNow().Pub()}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "allowed_ips is required") {
		t.Fatalf("empty AllowedIPs accepted: %v", err)
	}
	// The session's own render declares the default route explicitly and
	// must validate.
	sess := Config{
		PrivateKey: mustKeyNow(),
		Peers: []PeerConfig{{
			PublicKey:  mustKeyNow().Pub(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		}},
	}
	if err := sess.Validate(); err != nil {
		t.Fatalf("explicit default-route config rejected: %v", err)
	}
}

// TestKeyJSONRoundTripHex (NIT6): keys marshal as hex strings, unmarshal
// accepts hex AND the legacy array shape; values survive the round trip.
func TestKeyJSONRoundTripHex(t *testing.T) {
	k := mustKeyNow()
	blob, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if !strings.HasPrefix(s, `"`) || strings.Contains(s, "[") {
		t.Fatalf("key must marshal as a hex string, got %s", s)
	}
	var back Key
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("hex round-trip: %v", err)
	}
	if back != k {
		t.Fatal("hex round-trip changed the key")
	}

	// Legacy byte array still decodes.
	legacy, _ := json.Marshal(k[:])
	var back2 Key
	if err := json.Unmarshal(legacy, &back2); err != nil {
		t.Fatalf("legacy array: %v", err)
	}
	if back2 != k {
		t.Fatal("legacy array round-trip changed the key")
	}

	// Legacy base64 string still decodes.
	legacyB64, _ := json.Marshal(k.B64())
	var back3 Key
	if err := json.Unmarshal(legacyB64, &back3); err != nil {
		t.Fatalf("legacy base64: %v", err)
	}
	if back3 != k {
		t.Fatal("legacy base64 round-trip changed the key")
	}

	// Garbage is rejected.
	if err := json.Unmarshal([]byte(`"zzzz"`), &back); err == nil {
		t.Fatal("invalid hex accepted")
	}
	var back4 Key
	if err := json.Unmarshal([]byte(`"abcd"`), &back4); err == nil {
		t.Fatal("short hex accepted")
	}
}
