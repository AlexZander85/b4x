package transportwg

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// recordingHook captures every seam call without modifying buffers (WG1 hook
// bodies are inert no-ops by design; WG2 replaces the body, this test pins
// the CALL SITES in both directions).
type recordingHook struct {
	mu       sync.Mutex
	outbound [][]byte
	inbound  [][]byte
}

func (r *recordingHook) PatchOutbound(buf []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outbound = append(r.outbound, append([]byte(nil), buf...))
}

func (r *recordingHook) AdjustInbound(buf []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inbound = append(r.inbound, append([]byte(nil), buf...))
}

func (r *recordingHook) counts() (out, in int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.outbound), len(r.inbound)
}

func newLoopbackListener(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*net.UDPConn)
}

// TestSeamHooksInvokedBothDirections proves the seam sits on the wire paths:
// PatchOutbound fires in Send before the datagram leaves; AdjustInbound fires
// in the receive func before the buffer reaches the device. Buffers must be
// passed through byte-identical while hooks are inert.
func TestSeamHooksInvokedBothDirections(t *testing.T) {
	sink := newLoopbackListener(t)

	b := NewBind(SocketOptions{})
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) == 0 {
		t.Fatalf("open returned %d receive funcs", len(fns))
	}
	t.Cleanup(func() { _ = b.Close() })

	hook := &recordingHook{}
	b.SetDatagramHook(hook)

	ep, err := b.ParseEndpoint(sink.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("handshake-initiation-shaped-buffer")
	if err := b.Send([][]byte{payload}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	out := make([]byte, len(payload)+16)
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := sink.ReadFrom(out)
	if err != nil {
		t.Fatalf("listener read: %v", err)
	}
	if !bytes.Equal(out[:n], payload) {
		t.Fatalf("inert hook mutated outbound: %q", out[:n])
	}

	// Inbound path: another socket talks INTO the bind; run one ReceiveFunc.
	sender, err := net.Dial("udp4", "127.0.0.1:"+itoaPort(b.ActualPort()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	reply := []byte("cookie-reply-shaped-buffer")
	type rxResult struct {
		n   int
		buf []byte
		err error
	}
	rxCh := make(chan rxResult, 1)
	go func() {
		bufs := make([][]byte, 1)
		bufs[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		_, err := fns[0](bufs, sizes, eps)
		rxCh <- rxResult{n: sizes[0], buf: append([]byte(nil), bufs[0][:sizes[0]]...), err: err}
	}()
	if _, err := sender.Write(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-rxCh:
		if res.err != nil {
			t.Fatalf("receive fn: %v", res.err)
		}
		if !bytes.Equal(res.buf, reply) {
			t.Fatalf("inert hook mutated inbound: %q", res.buf)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receive func never returned")
	}

	outN, inN := hook.counts()
	if outN < 1 || inN < 1 {
		t.Fatalf("hook calls: outbound=%d inbound=%d, want >=1 each", outN, inN)
	}
}

// TestNilHookPassthroughZeroValue: default bind without any hook still moves
// datagrams (zero-value passthrough contract).
func TestNilHookPassthrough(t *testing.T) {
	sink := newLoopbackListener(t)
	b := NewBind(SocketOptions{})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	ep, _ := b.ParseEndpoint(sink.LocalAddr().String())
	payload := []byte("no-hook-datagram")
	if err := b.Send([][]byte{payload}, ep); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := sink.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("passthrough broken: n=%d err=%v", n, err)
	}
}

// TestSetMarkRequirePolicyFailsClosed pins the production posture: a policy
// that requires SO_MARK refuses mark-less updates regardless of platform.
func TestSetMarkRequirePolicyFailsClosed(t *testing.T) {
	b := NewBind(SocketOptions{RequireMark: true})
	if err := b.SetMark(0); err == nil {
		t.Fatal("RequireMark policy must reject mark=0")
	}
	ok := NewBind(SocketOptions{})
	if err := ok.SetMark(0); err != nil {
		t.Fatalf("unconstrained bind accepts mark=0 (store-only semantics): %v", err)
	}
}

// TestOpenTwiceFails pins ErrBindAlreadyOpen parity with upstream.
func TestOpenTwiceFails(t *testing.T) {
	b := NewBind(SocketOptions{})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open: got %v, want ErrBindAlreadyOpen", err)
	}
}
