package mtproto

import (
	"testing"
	"time"
)

func TestFirstDataZeroByteDoesNotDropAndProgressExtendsState(t *testing.T) {
	now := time.Unix(27000, 0)
	m := NewFirstDataMachine(now, DefaultFirstDataPolicy())
	if m.Tick(now.Add(6*time.Second)) != HandshakeSoftExpired {
		t.Fatal("soft deadline missing")
	}
	m.Observe(1, now.Add(7*time.Second))
	if m.State != HandshakeProgress {
		t.Fatal("progress not recorded")
	}
	if m.Tick(now.Add(29*time.Second)) == HandshakeHardExpired {
		t.Fatal("progress caused premature hard expiry")
	}
	m.Accept(now.Add(8 * time.Second))
	if m.State != HandshakeAccepted {
		t.Fatal("accept failed")
	}
}
