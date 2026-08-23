package nfq

import (
	"encoding/binary"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sock"
)

func TestApplyInWindowBadsumRestoresSeqAndBreaksCsum(t *testing.T) {
	pay := make([]byte, 200)
	pay[0] = 0x16
	orig := ipv4TCPPacket(5000, pay)
	cfg := &config.SetConfig{}
	cfg.Faking.SNI = true
	cfg.Faking.SNISeqLength = 1
	cfg.Faking.Strategy = "pastseq"
	cfg.Faking.SeqOffset = 10000
	fake := sock.BuildFakeSNIPacketV4(orig, cfg)
	if fake == nil {
		t.Fatal("build")
	}
	applyInWindowBadsumV4(fake, orig)
	if fake[8] != orig[8] {
		t.Fatalf("ttl %d want %d", fake[8], orig[8])
	}
	ip := int((fake[0] & 0x0F) * 4)
	oip := int((orig[0] & 0x0F) * 4)
	if binary.BigEndian.Uint32(fake[ip+4:ip+8]) != binary.BigEndian.Uint32(orig[oip+4:oip+8]) {
		t.Fatal("seq not restored to window")
	}
	if tcpChecksumLooksValidV4(fake) {
		t.Fatal("checksum should be bad")
	}
	if len(fake) > 1500 {
		t.Fatalf("still over MTU %d", len(fake))
	}
}
