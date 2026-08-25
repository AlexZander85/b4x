package fxvpn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestH3HappyEchoBidirectional(t *testing.T) {
	e := newFakeH3Edge(t)
	s := dialH3Test(t, e, "jwt-1")

	conn, err := s.OpenTunnel(context.Background(), "target.example:443")
	if err != nil {
		t.Fatalf("OpenTunnel: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello over handwritten h3")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := halfClose(conn); err != nil {
		t.Fatalf("close write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q", got)
	}
	if _, _, auth := e.counters(); auth != "Bearer jwt-1" {
		t.Fatalf("bearer = %q", auth)
	}
}

func TestH3WrongJWTIs407NotSwitchClass(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior("echo", 0, "the-real-token")
	s := dialH3Test(t, e, "forged")

	_, err := s.OpenTunnel(context.Background(), "x.example:80")
	var rej *ConnectRejectedError
	if !asConnectRejected(err, &rej) || rej.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("want 407, got %v", err)
	}
	if ClassifyDialError(err) != "" {
		t.Fatal("account-level rejection must not be a carrier class")
	}
}

func TestH3Quota429OnConnect(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior("", 429, "")
	s := dialH3Test(t, e, "jwt-1")

	_, err := s.OpenTunnel(context.Background(), "y.example:80")
	var rej *ConnectRejectedError
	if !asConnectRejected(err, &rej) || !rej.IsQuota() {
		t.Fatalf("want quota-flagged 429, got %v", err)
	}
}

func TestH3SilentDropReadsEOFFast(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior("silent", 0, "")
	s := dialH3Test(t, e, "jwt-1")

	conn, err := s.OpenTunnel(context.Background(), "quiet.example:443")
	if err != nil {
		t.Fatalf("open (200 expected): %v", err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 16))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) && err == nil {
			t.Fatalf("expected EOF, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("silent drop must surface immediately")
	}
}

func TestH3TeardownMidStreamErrors(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior("teardown", 0, "")
	s := dialH3Test(t, e, "jwt-1")

	conn, err := s.OpenTunnel(context.Background(), "rip.example:443")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	chunk := []byte("feed-h3!")
	if _, werr := conn.Write(chunk); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	buf := make([]byte, len(chunk))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo chunk before teardown: %v", err)
	}
	_ = halfClose(conn)
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 32))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("teardown must surface as read error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("teardown must not hang reads")
	}
}

func TestH3HangConnectBudgetFires(t *testing.T) {
	e := newFakeH3Edge(t)
	e.setBehavior("hang", 0, "")
	s := dialH3Test(t, e, "jwt-1")

	start := time.Now()
	_, err := s.OpenTunnel(context.Background(), "slow.example:80")
	if err == nil {
		t.Fatal("budget must fire on hang")
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatalf("budget too slow: %v", elapsed)
	}
}

func TestH3WatchDoneFlipsAliveOnConnDeath(t *testing.T) {
	e := newFakeH3Edge(t)
	s := dialH3Test(t, e, "jwt-1")

	conn, err := s.OpenTunnel(context.Background(), "z.example:80")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = conn.Close()
	if !s.IsAlive() {
		t.Fatal("session must stay alive after clean stream close")
	}

	// QUIC connection terminates (any initiator): watchDone must flip alive.
	_ = s.conn.CloseWithError(0, "conn death test")
	waitFor(t, 3*time.Second, func() bool { return !s.IsAlive() }, "alive flag did not flip on conn death")
}
