// fxvpn_bait_test.go: FX-M3 spec pins — the iptables/nftables bait rules
// match MarkFxvpnEgress exactly, carry the fxvpn-bait comment (idempotent
// cleanup), ride the engine's queue pool and keep --queue-bypass.
package tables

import (
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/packetmark"
)

func fxvpnBaitTestCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Queue.StartNum = 200
	return cfg
}

func TestFxvpnBaitIPTSpec(t *testing.T) {
	spec := fxvpnBaitIPTSpec(fxvpnBaitTestCfg())
	joined := strings.Join(spec, " ")
	for _, want := range []string{
		"0x400000/0x400000", // MarkFxvpnEgress (bit 22) exact match
		"fxvpn-bait",
		"NFQUEUE", "--queue-num", "200", "--queue-bypass",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("spec missing %q: %s", want, joined)
		}
	}
}

func TestFxvpnBaitNFTRule(t *testing.T) {
	rule := fxvpnBaitNFTRule(fxvpnBaitTestCfg())
	for _, want := range []string{
		"meta mark & 0x400000 == 0x400000",
		"fxvpn-bait", "bypass",
	} {
		if !strings.Contains(rule, want) {
			t.Fatalf("nft rule missing %q: %s", want, rule)
		}
	}
}

// TestFxvpnBaitMarkBitDisjoint pins the mark contract: the fxvpn bit must
// never overlap the opera bit, the canary control mask or ProcessedBit.
func TestFxvpnBaitMarkBitDisjoint(t *testing.T) {
	if packetmark.MarkFxvpnEgress&packetmark.MarkOperaEgress != 0 {
		t.Fatal("fxvpn/opera marks overlap")
	}
	if packetmark.MarkFxvpnEgress&packetmark.CanaryControlMask != 0 {
		t.Fatal("fxvpn mark overlaps the canary control mask")
	}
	if packetmark.MarkFxvpnEgress&packetmark.ProcessedMask != 0 {
		t.Fatal("fxvpn mark overlaps ProcessedBit")
	}
}
