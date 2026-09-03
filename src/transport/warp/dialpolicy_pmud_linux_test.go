//go:build linux

// PATCH-31 (N-8): the DisableUDPFragment knob pins the PMTUDISC socket
// option per family (assert the live option value; linux-only by nature).

package transportwarp

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// loopbackFor returns a bind address per UDP family.
func loopbackFor(network string) string {
	if network == "udp6" {
		return "[::1]:0"
	}
	return "127.0.0.1:0"
}

func assertPMTUDISC(t *testing.T, network string, want int) {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), network, loopbackFor(network))
	if err != nil {
		t.Fatalf("listen %s: %v", network, err)
	}
	defer pc.Close()
	raw, ok := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		t.Fatalf("%s packet conn exposes no RawConn", network)
	}
	sc, serr := raw.SyscallConn()
	if serr != nil {
		t.Fatalf("syscall conn: %v", serr)
	}
	policy := DialPolicy{DisableUDPFragment: true}
	if err := applyControlPlatform(policy, network, "", sc); err != nil {
		t.Fatalf("applyControlPlatform: %v", err)
	}
	var got int
	var gerr error
	cerr := sc.Control(func(fd uintptr) {
		var e error
		switch network {
		case "udp4":
			got, e = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
		case "udp6":
			got, e = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER)
		}
		gerr = e
	})
	if cerr != nil {
		t.Fatalf("control: %v", cerr)
	}
	if gerr != nil {
		t.Fatalf("getsockopt: %v", gerr)
	}
	if got != want {
		t.Fatalf("%s MTU_DISCOVER = %d, want %d (PMTUDISC_DO)", network, got, want)
	}
}

func TestDisableUDPFragmentPinsPMTUDISC(t *testing.T) {
	assertPMTUDISC(t, "udp4", unix.IP_PMTUDISC_DO)
	assertPMTUDISC(t, "udp6", unix.IPV6_PMTUDISC_DO)
}

// TestDisableUDPFragmentDefaultOff: the zero-value policy keeps the
// kernel-default PMTUDISC posture (sing-box-compatible fragmentation).
func TestDisableUDPFragmentDefaultOff(t *testing.T) {
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp4", loopbackFor("udp4"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	sc, serr := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	}).SyscallConn()
	if serr != nil {
		t.Fatal(serr)
	}
	if err := applyControlPlatform(DialPolicy{}, "udp4", "", sc); err != nil {
		t.Fatalf("zero policy must be a no-op: %v", err)
	}
	var got int
	var gerr error
	_ = sc.Control(func(fd uintptr) {
		got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if got == unix.IP_PMTUDISC_DO {
		t.Fatal("zero policy must not pin PMTUDISC_DO")
	}
}
