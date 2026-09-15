package dns

import (
	"encoding/binary"
	"testing"
	"time"
)

func encodeTestName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0}
	}
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			continue
		}
		if i > start {
			out = append(out, byte(i-start))
			out = append(out, name[start:i]...)
		}
		start = i + 1
	}
	return append(out, 0)
}

func testNXDOMAIN(withSOA bool) []byte {
	q := BuildQuery("missing.example", 0x1234, 1)
	resp := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8183) // response, RD, RA, NXDOMAIN
	if !withSOA {
		return resp
	}
	binary.BigEndian.PutUint16(resp[8:10], 1)
	rr := []byte{0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 120}
	rdata := append(encodeTestName("ns1.example"), encodeTestName("hostmaster.example")...)
	tail := make([]byte, 20)
	binary.BigEndian.PutUint32(tail[0:4], 1)
	binary.BigEndian.PutUint32(tail[4:8], 3600)
	binary.BigEndian.PutUint32(tail[8:12], 600)
	binary.BigEndian.PutUint32(tail[12:16], 86400)
	binary.BigEndian.PutUint32(tail[16:20], 60)
	rdata = append(rdata, tail...)
	rr = append(rr, byte(len(rdata)>>8), byte(len(rdata)))
	rr = append(rr, rdata...)
	return append(resp, rr...)
}

func TestInspectResponseMetadataRequiresAuthoritySOAForNegativeProof(t *testing.T) {
	bare, err := InspectResponseMetadata(testNXDOMAIN(false))
	if err != nil {
		t.Fatal(err)
	}
	if bare.RCode != 3 || bare.HasNegativeProof() {
		t.Fatalf("bare NXDOMAIN metadata = %+v", bare)
	}

	proved, err := InspectResponseMetadata(testNXDOMAIN(true))
	if err != nil {
		t.Fatal(err)
	}
	if proved.RCode != 3 || !proved.HasNegativeProof() {
		t.Fatalf("SOA-backed NXDOMAIN metadata = %+v", proved)
	}
	if proved.NegativeTTL != 60*time.Second {
		t.Fatalf("negative TTL = %s, want 60s", proved.NegativeTTL)
	}
}

func TestInspectResponseMetadataRejectsTrailingGarbage(t *testing.T) {
	msg := append(testNXDOMAIN(true), 0xde, 0xad)
	if _, err := InspectResponseMetadata(msg); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
}
