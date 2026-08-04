package nfq

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fixtures"
)

// fakePacketInjector records raw packets without touching real sockets.
type fakePacketInjector struct {
	sent4 int
	sent6 int
	last4 []byte
	last6 []byte
	err   error
}

func (f *fakePacketInjector) SendIPv4(packet []byte, dst net.IP) error {
	if f.err != nil {
		return f.err
	}
	f.sent4++
	f.last4 = append([]byte(nil), packet...)
	return nil
}

func (f *fakePacketInjector) SendIPv6(packet []byte, dst net.IP) error {
	if f.err != nil {
		return f.err
	}
	f.sent6++
	f.last6 = append([]byte(nil), packet...)
	return nil
}

func buildTestIPv4TCPPacket(t *testing.T, payload []byte, seq uint32, sport, dport uint16) []byte {
	t.Helper()
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 6
	binary.BigEndian.PutUint16(pkt[10:12], 0) // checksum is rebuilt by the executor
	copy(pkt[12:16], net.IPv4(192, 0, 2, 1).To4())
	copy(pkt[16:20], net.IPv4(203, 0, 113, 10).To4())
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	pkt[32] = 0x50 // data offset 5
	pkt[33] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(pkt[34:36], 65535)
	if len(payload) > 0 {
		copy(pkt[40:], payload)
	}
	return pkt
}

func buildTestIPv6TCPPacket(t *testing.T, payload []byte, seq uint32, sport, dport uint16) []byte {
	t.Helper()
	pkt := make([]byte, 60+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(20+len(payload)))
	pkt[6] = 6 // next header: TCP
	copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
	copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(pkt[40:42], sport)
	binary.BigEndian.PutUint16(pkt[42:44], dport)
	binary.BigEndian.PutUint32(pkt[44:48], seq)
	pkt[52] = 0x50
	pkt[53] = 0x18
	binary.BigEndian.PutUint16(pkt[54:56], 65535)
	if len(payload) > 0 {
		copy(pkt[60:], payload)
	}
	return pkt
}

// actionExecutorTestConfig returns a set config whose every legacy technique is
// off and the fragmentation strategy is "none", so dropAndInjectTCP reaches the
// centralized action executor path.
func actionExecutorTestConfig(t *testing.T) (*config.Config, *config.SetConfig) {
	t.Helper()
	cfg := config.NewConfig()
	set := config.NewSetConfig()
	set.Enabled = true
	set.Fragmentation.Strategy = config.ConfigNone
	set.Fragmentation.StrategyPool = nil
	set.Faking.SNI = false
	set.Faking.SNIMutation.Mode = config.ConfigOff
	set.TCP.Desync.Mode = config.ConfigOff
	set.TCP.Desync.PostDesync = false
	set.TCP.Win.Mode = config.ConfigOff
	set.TCP.DropSACK = false
	set.TCP.SynFake = false
	cfg.Sets = []*config.SetConfig{&set}
	return &cfg, &set
}

func TestExecuteActionPlanAppliedViaIPv4DropPath(t *testing.T) {
	_, set := actionExecutorTestConfig(t)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(nil, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)

	w.dropAndInjectTCP(set, raw, dst)

	if fake.sent4 != 1 {
		t.Fatalf("expected exactly one injected packet via the action executor, got %d", fake.sent4)
	}
	if fake.sent6 != 0 {
		t.Fatalf("unexpected IPv6 send on IPv4 path: %d", fake.sent6)
	}
	if err := action.ValidatePacket(fake.last4); err != nil {
		t.Fatalf("executor-built packet failed validation: %v", err)
	}
	if got := binary.BigEndian.Uint32(fake.last4[24:28]); got != 1000 {
		t.Fatalf("sequence not preserved: got %d want 1000", got)
	}
	if got := fake.last4[40:]; !bytes.Equal(got, hello) {
		t.Fatalf("payload mismatch: got %d bytes want %d", len(got), len(hello))
	}
}

func TestExecuteActionPlanAppliedViaIPv6DropPath(t *testing.T) {
	_, set := actionExecutorTestConfig(t)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv6TCPPacket(t, hello, 2000, 51001, 443)
	dst := net.ParseIP("2001:db8::2")

	fake := &fakePacketInjector{}
	w := NewWorkerWithQueue(nil, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)

	w.dropAndInjectTCPv6(set, raw, dst)

	if fake.sent6 != 1 {
		t.Fatalf("expected exactly one injected IPv6 packet via the action executor, got %d", fake.sent6)
	}
	if fake.sent4 != 0 {
		t.Fatalf("unexpected IPv4 send on IPv6 path: %d", fake.sent4)
	}
	if err := action.ValidatePacket(fake.last6); err != nil {
		t.Fatalf("executor-built IPv6 packet failed validation: %v", err)
	}
	if got := binary.BigEndian.Uint32(fake.last6[44:48]); got != 2000 {
		t.Fatalf("sequence not preserved: got %d want 2000", got)
	}
	if got := fake.last6[60:]; !bytes.Equal(got, hello) {
		t.Fatalf("payload mismatch: got %d bytes want %d", len(got), len(hello))
	}
}

func TestExecuteActionPlanFailsOpen(t *testing.T) {
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 64)
	raw := buildTestIPv4TCPPacket(t, hello, 3000, 51002, 443)
	raw6 := buildTestIPv6TCPPacket(t, hello, 4000, 51003, 443)
	dst := net.IPv4(203, 0, 113, 10)
	ctx := context.Background()

	t.Run("nil-sender", func(t *testing.T) {
		w := NewWorkerWithQueue(nil, 0)
		w.actionMark = capture.ProcessedMarkFor(1)
		if w.executeActionPlan(ctx, raw, dst, false) {
			t.Fatal("executeActionPlan must fail open when the injector is not attached")
		}
	})

	t.Run("nil-mark", func(t *testing.T) {
		fake := &fakePacketInjector{}
		w := NewWorkerWithQueue(nil, 0)
		w.actionSender = fake
		if w.executeActionPlan(ctx, raw, dst, false) {
			t.Fatal("executeActionPlan must fail open without a processed provenance mark")
		}
		if fake.sent4 != 0 {
			t.Fatalf("no packet may be sent on a failed plan, got %d", fake.sent4)
		}
	})

	t.Run("short-raw", func(t *testing.T) {
		fake := &fakePacketInjector{}
		w := NewWorkerWithQueue(nil, 0)
		w.actionSender = fake
		w.actionMark = capture.ProcessedMarkFor(1)
		if w.executeActionPlan(ctx, []byte{1, 2, 3}, dst, false) {
			t.Fatal("executeActionPlan must fail open on truncated packets")
		}
	})

	t.Run("empty-payload", func(t *testing.T) {
		fake := &fakePacketInjector{}
		w := NewWorkerWithQueue(nil, 0)
		w.actionSender = fake
		w.actionMark = capture.ProcessedMarkFor(1)
		noPayload := buildTestIPv4TCPPacket(t, nil, 3000, 51002, 443)
		if w.executeActionPlan(ctx, noPayload, dst, false) {
			t.Fatal("executeActionPlan must fail open when there is no payload")
		}
		if fake.sent4 != 0 {
			t.Fatalf("no packet may be sent on an empty payload, got %d", fake.sent4)
		}
	})

	t.Run("sender-error", func(t *testing.T) {
		fake := &fakePacketInjector{err: errors.New("raw send failed")}
		w := NewWorkerWithQueue(nil, 0)
		w.actionSender = fake
		w.actionMark = capture.ProcessedMarkFor(1)
		if w.executeActionPlan(ctx, raw, dst, false) {
			t.Fatal("executeActionPlan must fail open when the injector returns an error")
		}
		if fake.sent4 != 0 {
			t.Fatalf("failed injector must not report a sent packet, got %d", fake.sent4)
		}
	})

	t.Run("v6-sender-error", func(t *testing.T) {
		fake := &fakePacketInjector{err: errors.New("raw send failed")}
		w := NewWorkerWithQueue(nil, 0)
		w.actionSender = fake
		w.actionMark = capture.ProcessedMarkFor(1)
		if w.executeActionPlan(ctx, raw6, dst, true) {
			t.Fatal("executeActionPlan must fail open for IPv6 when the injector returns an error")
		}
		if fake.sent6 != 0 {
			t.Fatalf("failed injector must not report a sent IPv6 packet, got %d", fake.sent6)
		}
	})
}
