package geodat

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urlesistiana/v2dat/v2data"
	"google.golang.org/protobuf/proto"
)

func TestReadCountryCode(t *testing.T) {
	// field 1 (0x0A), length, bytes "RU".
	msg := []byte{0x0A, 0x02, 'R', 'U'}
	got, err := readCountryCode(msg)
	if err != nil || got != "ru" {
		t.Fatalf("readCountryCode = %q,%v want ru,nil", got, err)
	}
	// Empty input -> error.
	if _, err := readCountryCode(nil); err == nil {
		t.Fatal("empty input must fail")
	}
	// Wrong wire tag -> error.
	if _, err := readCountryCode([]byte{0x12, 0x01, 'x'}); err == nil {
		t.Fatal("wrong wire tag must fail")
	}
	// Malformed varint -> error.
	if _, err := readCountryCode([]byte{0x0A, 0x80}); err == nil {
		t.Fatal("truncated varint must fail")
	}
	// Declared length beyond buffer -> error.
	if _, err := readCountryCode([]byte{0x0A, 0x05, 'R', 'U'}); err == nil {
		t.Fatal("truncated string must fail")
	}
}

func TestSplitAttrs(t *testing.T) {
	tag, attrs := splitAttrs("youtube")
	if tag != "youtube" || attrs != nil {
		t.Fatalf("plain tag = %q,%v", tag, attrs)
	}
	tag, attrs = splitAttrs("cn@attr1@attr2")
	if tag != "cn" || len(attrs) != 2 {
		t.Fatalf("tag with attrs = %q,%v", tag, attrs)
	}
	if _, ok := attrs["attr1"]; !ok {
		t.Fatal("attr1 missing")
	}
	if _, ok := attrs["attr2"]; !ok {
		t.Fatal("attr2 missing")
	}
}

func TestConvertV2DomainToTextPrefixes(t *testing.T) {
	var buf bytes.Buffer
	domains := []*v2data.Domain{
		{Type: v2data.Domain_Plain, Value: "google"},
		{Type: v2data.Domain_Regex, Value: `\.youtube\.com$`},
		{Type: v2data.Domain_Full, Value: "example.com"},
		{Type: v2data.Domain_Domain, Value: "domain.example"},
	}
	if err := convertV2DomainToText(domains, &buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	want := []string{"keyword:google", "regexp:\\.youtube\\.com$", "full:example.com", "domain.example"}
	if len(lines) != len(want) {
		t.Fatalf("lines = %v", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestConvertV2CidrToTextDeterministicAndErrors(t *testing.T) {
	var buf bytes.Buffer
	cidrs := []*v2data.CIDR{
		{Ip: []byte{192, 0, 2, 0}, Prefix: 24},
		{Ip: []byte{203, 0, 113, 10}, Prefix: 32},
	}
	if err := convertV2CidrToText(cidrs, &buf); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "192.0.2.0/24\n203.0.113.10/32\n" {
		t.Fatalf("cidr output = %q", got)
	}
	// Invalid IP length -> error.
	if err := convertV2CidrToText([]*v2data.CIDR{{Ip: []byte{1, 2, 3}, Prefix: 24}}, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid IP must fail")
	}
	// Invalid prefix -> error.
	if err := convertV2CidrToText([]*v2data.CIDR{{Ip: []byte{1, 2, 3, 4}, Prefix: 40}}, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid prefix must fail")
	}
}

// writeGeoSiteFile writes a minimal v2dat GeoIP wire stream with one entry
// per provided (tag, cidrs) pair, mirroring streamGeoIP's expected framing.
func writeGeoIPFile(t *testing.T, path string, entries map[string][]*v2data.CIDR) {
	t.Helper()
	var buf bytes.Buffer
	for tag, cidrs := range entries {
		msg, err := proto.Marshal(&v2data.GeoIP{CountryCode: tag, Cidr: cidrs})
		if err != nil {
			t.Fatal(err)
		}
		buf.WriteByte(0x0A) // field 1 wire tag (length-delimited)
		var lenBuf [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(lenBuf[:], uint64(len(msg)))
		buf.Write(lenBuf[:n])
		buf.Write(msg)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadIpsFromCategoriesStreamsAndFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.dat")
	writeGeoIPFile(t, path, map[string][]*v2data.CIDR{
		"RU": {{Ip: []byte{192, 0, 2, 0}, Prefix: 24}},
		"US": {{Ip: []byte{198, 51, 100, 0}, Prefix: 24}},
	})
	ips, err := LoadIpsFromCategories(path, []string{"us"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "198.51.100.0/24" {
		t.Fatalf("filtered ips = %v", ips)
	}
	// Missing file degrades to empty result (categories ignored).
	empty, err := LoadIpsFromCategories(filepath.Join(dir, "missing.dat"), []string{"ru"})
	if err != nil || len(empty) != 0 {
		t.Fatalf("missing file = %v,%v want empty,nil", empty, err)
	}
	// Empty categories short-circuit.
	if got, err := LoadIpsFromCategories(path, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty categories = %v,%v", got, err)
	}
}

func TestStreamGeoIPRejectsBadWireTag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.dat")
	if err := os.WriteFile(path, []byte{0x12, 0x01, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	err := streamGeoIP(path, []string{"ru"}, func(string, *v2data.GeoIP) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "wire tag") {
		t.Fatalf("bad wire tag error = %v", err)
	}
}

func FuzzReadCountryCodeNeverPanics(f *testing.F) {
	f.Add([]byte{0x0A, 0x02, 'R', 'U'})
	f.Add([]byte{0x0A})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = readCountryCode(b)
	})
}
