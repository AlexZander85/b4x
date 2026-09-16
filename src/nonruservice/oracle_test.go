package nonruservice

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/urlesistiana/v2dat/v2data"
	"google.golang.org/protobuf/proto"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	return netip.MustParsePrefix(s)
}

// oracleFixture builds a small country index directly (no geoip.dat round
// trip — the loader has its own test in geodat).
func oracleFixture(t *testing.T) *geoOracle {
	t.Helper()
	o := &geoOracle{
		entries: []oracleEntry{
			{net: mustPrefix(t, "1.0.0.0/24"), country: "1", isPseudo: true},
			{net: mustPrefix(t, "45.10.40.0/21"), country: "ru"},
			{net: mustPrefix(t, "45.132.16.0/21"), country: "ru"},
			{net: mustPrefix(t, "62.76.0.0/14"), country: "ru"},
			{net: mustPrefix(t, "81.2.0.0/16"), country: "gb"},
			{net: mustPrefix(t, "81.9.0.0/16"), country: "de"},
			{net: mustPrefix(t, "104.16.0.0/16"), country: "ca"}, // nesting: the /12 last wins (backward scan)
			{net: mustPrefix(t, "104.16.0.0/12"), country: "us"},
			{net: mustPrefix(t, "192.0.2.0/24"), country: "private", isPseudo: true},
			{net: mustPrefix(t, "198.51.100.0/24"), country: "nl"},
		},
	}
	return o
}

func TestOracleClassify(t *testing.T) {
	o := oracleFixture(t)
	cases := []struct {
		ip   string
		want string
	}{
		{"1.0.0.7", ""},         // pseudo-tag (cloudflare "1") never classifies
		{"1.0.1.7", ""},         // outside every prefix
		{"62.76.3.4", "ru"},     // plain hit
		{"81.2.33.44", "gb"},    // adjacent /16s of different countries
		{"81.9.33.44", "de"},    //
		{"104.16.5.5", "us"},    // the /12 wins (lowest network address)
		{"104.17.5.5", "us"},    // only the /12 contains
		{"192.0.2.9", ""},       // private pseudo-tag
		{"198.51.100.1", "nl"},  // exact network
		{"203.0.113.5", ""},     // unmatched
		{"::1", ""},             // v6 never classifies (the index is v4)
		{"::ffff:81.2.0.5", ""}, // 4-in-6 stays v6 for the v4 index
	}
	for _, tc := range cases {
		if got := o.Classify(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("Classify(%s) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestOracleNilSafe(t *testing.T) {
	var o *geoOracle
	if got := o.Classify(netip.MustParseAddr("81.2.0.1")); got != "" {
		t.Fatalf("nil oracle classified %q, want \"\"", got)
	}
}

func TestLoadGeoOracleFromDat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.dat")

	// Synthesize a v2dat geoip.dat stream (the geodat test canon framing).
	var buf []byte
	add := func(tag string, cidrs ...*v2data.CIDR) {
		msg, err := proto.Marshal(&v2data.GeoIP{CountryCode: tag, Cidr: cidrs})
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, 0x0A)
		var lb [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(lb[:], uint64(len(msg)))
		buf = append(buf, lb[:n]...)
		buf = append(buf, msg...)
	}
	add("ru", &v2data.CIDR{Ip: []byte{62, 76, 0, 0}, Prefix: 14})
	add("de", &v2data.CIDR{Ip: []byte{81, 9, 0, 0}, Prefix: 16})
	add("1", &v2data.CIDR{Ip: []byte{1, 0, 0, 0}, Prefix: 24})
	add("xx", &v2data.CIDR{Ip: []byte{0x20, 0x01, 0x0d, 0xb8}, Prefix: 32}) // v6 row: ignored by the v4 index
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	o, err := loadGeoOracle(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := o.Classify(netip.MustParseAddr("62.76.1.1")); got != "ru" {
		t.Fatalf("ru classify = %q", got)
	}
	if got := o.Classify(netip.MustParseAddr("81.9.4.4")); got != "de" {
		t.Fatalf("de classify = %q", got)
	}
	if got := o.Classify(netip.MustParseAddr("1.0.0.1")); got != "" {
		t.Fatalf("pseudo classify = %q, want \"\"", got)
	}
	if got := o.Classify(netip.MustParseAddr("2001:db8::1")); got != "" {
		t.Fatalf("v6 classify = %q, want \"\"", got)
	}
}

func TestLoadGeoOracleMissingFile(t *testing.T) {
	if _, err := loadGeoOracle(filepath.Join(t.TempDir(), "absent.dat")); err == nil {
		t.Fatal("missing file must fail the oracle load (the caller reports the honest posture)")
	}
}
