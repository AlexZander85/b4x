package proton

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/transport/wgprobe/wgprobetest"
)

// TestProbeHandshakeRTTStopYields pins the b4x-077 yield seam: a probe whose
// Stop predicate is already true must return at once without sending, so a
// waiting session start gets the key immediately.
func TestProbeHandshakeRTTStopYields(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("silent node: %v", err)
	}
	defer pc.Close()

	privB64 := base64.StdEncoding.EncodeToString(mustHexBytes(t,
		"a01010101010101010101010101010101010101010101010101010101010101f"))
	validPeer := wgprobetest.NewResponder().PublicKey()
	peerB64 := base64.StdEncoding.EncodeToString(validPeer[:])

	started := time.Now()
	res := ProbeHandshakeRTT(context.Background(), privB64, peerB64,
		pc.LocalAddr().(*net.UDPAddr),
		ProbeHandshakeConfig{
			Timeout: 2 * time.Second,
			Stop:    func() bool { return true },
		})
	if res.OK {
		t.Fatal("a stopped probe must never report success")
	}
	if res.Attempts != 0 {
		t.Fatalf("a stopped probe must not try a local port, attempts=%d", res.Attempts)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("stopped probe took %v, want immediate", elapsed)
	}
}
