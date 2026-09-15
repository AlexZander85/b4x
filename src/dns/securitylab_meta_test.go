package dns

import (
	"encoding/binary"
	"testing"
)

func TestSecurityLabForgedNXDOMAINMetadata(t *testing.T) {
	msg := BuildQuery("blocked.example", 0x2222, 1)
	// QR=1, AA=1, RD=1, RA=1, RCODE=NXDOMAIN; AN/NS/AR stay zero.
	binary.BigEndian.PutUint16(msg[2:4], 0x8583)
	meta, err := InspectResponseMetadata(msg)
	if err != nil {
		t.Fatal(err)
	}
	if meta.RCode != 3 || !meta.Authoritative {
		t.Fatalf("unexpected forged metadata: %+v", meta)
	}
	if meta.AuthorityCount != 0 || meta.HasNegativeProof() {
		t.Fatalf("AA=1 with empty authority must not be accepted as negative proof: %+v", meta)
	}
}
