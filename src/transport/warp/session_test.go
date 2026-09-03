package transportwarp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// newTestPriv makes an enrolled-shape client key.
func newTestPriv(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privB64, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func cfgForServer(t *testing.T, fs *fakeServer) SessionConfig {
	return SessionConfig{
		Endpoint:  fs.addr(),
		ClientKey: newTestPriv(t),
		Pin:       fs.pinPub(),
		LocalV4:   [4]byte{172, 16, 0, 2},
	}
}

func cfgForServerAddr(t *testing.T, addr string, pin *ecdsa.PublicKey) SessionConfig {
	return SessionConfig{
		Endpoint:  netip.MustParseAddrPort(addr),
		ClientKey: newTestPriv(t),
		Pin:       pin,
		LocalV4:   [4]byte{172, 16, 0, 2},
	}
}

func TestSessionEchoRoundTripAndValidation(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()

	sess, res, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatalf("dial: %v (class=%s status=%d)", err, res.FailureClass, res.Status)
	}
	defer sess.Close()
	if res.Status != 200 || res.FailureClass != "" || res.PinDigest == "" {
		t.Fatalf("bad result %+v", res)
	}

	if err := sess.ValidateDataPlane(context.Background()); err != nil {
		t.Fatalf("data-plane validation failed: %v", err)
	}

	pkt := make([]byte, DefaultMTU)
	for i := range pkt {
		pkt[i] = byte(i % 251)
	}
	if err := sess.WritePacket(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := sess.ReadPacket(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatalf("echo corrupted: got %d bytes, first=%d want-first=%d", len(got), got[0], pkt[0])
	}
	_, capsules := fs.counters()
	if capsules < 3 {
		t.Fatalf("server saw %d capsules, want >=3 (validation probes)", capsules)
	}
}

func TestSessionConnectStatuses(t *testing.T) {
	for _, status := range []int{403, 429, 500} {
		fs := newFakeServer(t)
		fs.setBehavior(status, false, false, 0)

		sess, res, err := DialSession(context.Background(), cfgForServer(t, fs))
		fs.close()
		if err == nil {
			sess.Close()
			t.Fatalf("status %d: expected failure", status)
		}
		if res.FailureClass != FailureConnectReject {
			t.Fatalf("status %d: class=%s want %s", status, res.FailureClass, FailureConnectReject)
		}
		if res.Status != status {
			t.Fatalf("status reported %d want %d", res.Status, status)
		}
	}
}

func TestSessionPinMismatch(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()

	other := newTestKey(t) // wrong trust anchor
	cfg := cfgForServer(t, fs)
	cfg.Pin = &other.PublicKey

	sess, res, err := DialSession(context.Background(), cfg)
	if err == nil {
		sess.Close()
		t.Fatal("mismatched pin accepted")
	}
	if res.FailureClass != FailureTLSPin {
		t.Fatalf("class=%s want %s", res.FailureClass, FailureTLSPin)
	}
	if !errors.Is(err, ErrPinMismatch) && res.FailureClass != FailureTLSPin {
		t.Fatalf("error chain lost pin reason: %v", err)
	}
}

func TestSessionTCPRefused(t *testing.T) {
	// grab a port then release it: nothing listens there
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	priv := newTestPriv(t)
	cfg2 := cfgForServerAddr(t, addr, &priv.PublicKey)

	_, res, err := DialSession(context.Background(), cfg2)
	if err == nil {
		t.Fatal("dial to dead port succeeded")
	}
	if res.FailureClass != FailureTCPConnect {
		t.Fatalf("class=%s want %s", res.FailureClass, FailureTCPConnect)
	}
}

func TestSessionForeignCapsuleSkipped(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	fs.setBehavior(200, false, true, 0) // prepend unknown capsule before each echo

	sess, _, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.ValidateDataPlane(context.Background()); err != nil {
		t.Fatalf("validation: %v", err)
	}
	pkt := []byte("hello-tunnel")
	if err := sess.WritePacket(pkt); err != nil {
		t.Fatal(err)
	}
	got, err := sess.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatalf("payload not extracted cleanly: %q", got)
	}
}

func TestDataPlaneValidationTimeoutOnSilentDrop(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	fs.setBehavior(200, true, false, 0) // control ok, traffic silently dropped

	cfg := cfgForServer(t, fs)
	cfg.ValidateWindow = 1200 * time.Millisecond
	cfg.ProbeInterval = 200 * time.Millisecond

	sess, _, err := DialSession(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	err = sess.ValidateDataPlane(context.Background())
	if !errors.Is(err, ErrValidationTimeout) {
		t.Fatalf("want ErrValidationTimeout, got %v", err)
	}
	select {
	case <-sess.Done():
	default:
		t.Fatal("session must be torn down after validation timeout")
	}
}

func TestSessionTeardownMidStream(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	fs.setBehavior(200, false, false, 1) // echo once, then kill stream

	sess, _, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// First capsule echoes normally...
	if err := sess.WritePacket([]byte("one")); err != nil {
		t.Fatal(err)
	}
	got, err := sess.ReadPacket(context.Background())
	if err != nil || string(got) != "one" {
		t.Fatalf("first echo: got %q err=%v", got, err)
	}

	// ...second capsule triggers the abrupt mid-stream teardown.
	if err := sess.WritePacket([]byte("two")); err != nil {
		t.Fatalf("write two: %v", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session not closed after server teardown")
	}
}

func TestSessionPacketTooBig(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	sess, _, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	big := make([]byte, DefaultMTU+1)
	if err := sess.WritePacket(big); !errors.Is(err, ErrPacketTooBig) {
		t.Fatalf("want ErrPacketTooBig, got %v", err)
	}
}

func TestSessionConcurrentWritersKeepFraming(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	sess, _, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.ValidateDataPlane(context.Background()); err != nil {
		t.Fatal(err)
	}

	const n = 8
	payloads := make([][]byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		payloads[i] = bytes.Repeat([]byte{byte('A' + i)}, 100+i)
		wg.Add(1)
		go func(p []byte) {
			defer wg.Done()
			if err := sess.WritePacket(p); err != nil {
				t.Errorf("write: %v", err)
			}
		}(payloads[i])
	}
	wg.Wait()

	seen := make(map[string]bool)
	for i := 0; i < n; i++ {
		got, err := sess.ReadPacket(context.Background())
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if seen[string(got)] {
			t.Fatalf("duplicate/corrupt frame: %q", got[:min(len(got), 8)])
		}
		seen[string(got)] = true
	}
	want := map[string]bool{}
	for _, p := range payloads {
		want[string(p)] = true
	}
	for k := range seen {
		if !want[k] {
			t.Fatalf("unexpected payload %q", k[:min(len(k), 8)])
		}
	}
}

func TestReadPacketHonorsContextCancellation(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	sess, _, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := sess.ReadPacket(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want ctx deadline, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation ignored for %v", elapsed)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
