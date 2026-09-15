package dns

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func testARecord(ip [4]byte) []byte {
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	return append(rr, ip[:]...)
}

func TestStructuredResponseDoesNotFoldAdditionalGlueIntoAnswers(t *testing.T) {
	msg := BuildQuery("example.com", 0x4242, 1)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[6:8], 1)  // one real answer
	binary.BigEndian.PutUint16(msg[10:12], 1) // one additional/glue record
	msg = append(msg, testARecord([4]byte{93, 184, 216, 34})...)
	msg = append(msg, testARecord([4]byte{203, 0, 113, 99})...)

	obs, err := ParseResponse(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Answers) != 1 {
		t.Fatalf("answers=%d, want exactly Answer-section record", len(obs.Answers))
	}
	want := netip.MustParseAddr("93.184.216.34")
	if obs.Answers[0].IP != want {
		t.Fatalf("answer=%s want=%s", obs.Answers[0].IP, want)
	}
}
