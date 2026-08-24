// In-process interop regressions, adapted from upstream genTestPair
// (device/device_test.go:167-214) per design §10 WG1 verification: two
// devices inside one process, configs as IpcSet strings rendered by OUR
// Config.IPCString. Topologies:
//
//	vanilla <-> vanilla      (wire identical to wireguard-go)
//	AWG-full <-> AWG-full    (jc/jmin/jmax + S1-4 + H-ranges both ends)
//	AWG-junk <-> vanilla     (client-side-only junk against a vanilla peer —
//	                          the Cloudflare-edge compatibility shape)
//
// Transport variants: upstream ChannelBinds (deterministic) AND our own Bind
// over real loopback UDP (exercises socket creation and seam paths), plus the
// netstack handshake smoke (CI gate for ModeNetstack) and the manual kernel-
// TUN privileged gate.
package transportwg

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"golang.org/x/crypto/curve25519"
)

// ---- helpers shared by interop tests ----

func ip4(b [4]byte) netip.Addr { return netip.AddrFrom4(b) }

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func itoaPort(p uint16) string { return strconv.Itoa(int(p)) }

func mustKeys(t *testing.T) (privA, privB Key, pubA, pubB Key) {
	t.Helper()
	for _, slot := range []*Key{&privA, &privB} {
		k, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		*slot = k
	}
	pubA = mustPub(t, privA)
	pubB = mustPub(t, privB)
	return
}

func mustPub(t *testing.T, priv Key) Key {
	t.Helper()
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var pub Key
	copy(pub[:], out)
	return pub
}

// portCaptureBind wraps a conn.Bind to record the port Open returned
// (upstream reads dev.net.port which is unexported for us).
type portCaptureBind struct {
	conn.Bind
	mu   sync.Mutex
	port uint16
}

func (b *portCaptureBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err == nil {
		b.mu.Lock()
		b.port = actual
		b.mu.Unlock()
	}
	return fns, actual, err
}

func (b *portCaptureBind) actualPort() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.port
}

type pairSide struct {
	ip   [4]byte
	tun  *tuntest.ChannelTUN
	dev  *device.Device
	pcap *portCaptureBind // always set; wraps either bind flavor
}

func (s *pairSide) bindPort() uint16 { return s.pcap.actualPort() }

type pairConfig struct {
	name       string
	profiles   [2]func() Profile
	useRealUDP bool
}

func awgFullProfile() Profile {
	r := func(lo, hi uint32) *Range { return &Range{Lo: lo, Hi: hi} }
	return Profile{
		JunkCount: 5, JunkMin: 500, JunkMax: 1000,
		PadInit: 15, PadResponse: 18, PadCookie: 20, PadTransport: 25,
		HeaderInit:      r(123456, 123500),
		HeaderResponse:  r(67543, 67550),
		HeaderCookie:    r(123123, 123200),
		HeaderTransport: r(32345, 32350),
	}
}

// junkOnlyProfile is the vanilla-safe family: client-side-only parameters.
func junkOnlyProfile() Profile {
	return Profile{
		JunkCount: 4, JunkMin: 40, JunkMax: 70,
		InitPacket: [5]string{"<b 0xce00000044d0><t><r 8>"},
	}
}

func newInteropPair(t *testing.T, cfg pairConfig) [2]*pairSide {
	t.Helper()
	privA, privB, pubA, pubB := mustKeys(t)

	var binds [2]conn.Bind
	if cfg.useRealUDP {
		for i := range binds {
			binds[i] = &portCaptureBind{Bind: NewBind(SocketOptions{})}
		}
	} else {
		chans := bindtest.NewChannelBinds()
		for i := range binds {
			binds[i] = &portCaptureBind{Bind: chans[i]}
		}
	}

	keys := [2]Key{privA, privB}
	pubs := [2]Key{pubA, pubB}
	var sides [2]*pairSide
	for i := range sides {
		s := &pairSide{}
		s.tun = tuntest.NewChannelTUN()
		s.ip = [4]byte{1, 0, 0, byte(i + 1)}
		c := Config{
			PrivateKey: keys[i],
			Profile:    cfg.profiles[i](),
			Peers: []PeerConfig{{
				PublicKey: pubs[i^1],
				// Narrow /32 like upstream genConfigs: keeps the warmup
				// packet below unroutable so it never reaches the wire.
				AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip4([4]byte{1, 0, 0, byte(i ^ 1 + 1)}), 32)},
			}},
		}
		ipc, err := c.IPCString()
		if err != nil {
			t.Fatalf("%s: render side %d: %v", cfg.name, i, err)
		}
		var dlog *device.Logger
		if testing.Verbose() { // DEBUG(wg1): verbose device log under -v
			dlog = device.NewLogger(device.LogLevelVerbose, fmt.Sprintf("dev%d: ", i))
		} else {
			dlog = DeviceLogger(nil)
		}
		dev := device.NewDevice(s.tun.TUN(), binds[i], dlog)
		if err := dev.IpcSet(ipc); err != nil {
			t.Fatalf("%s: IpcSet side %d: %v\nipc:\n%s", cfg.name, i, err, ipc)
		}
		if err := dev.Up(); err != nil {
			t.Fatalf("%s: Up side %d: %v", cfg.name, i, err)
		}
		t.Cleanup(dev.Close)
		s.dev = dev
		s.pcap = binds[i].(*portCaptureBind)
		sides[i] = s
		if s.bindPort() == 0 {
			t.Fatalf("%s: side %d did not report a listen port", cfg.name, i)
		}
	}

	// Cross-wire endpoints now that both ports are known.
	for i := range sides {
		endpointCfg := "public_key=" + pubs[i^1].Hex() + "\nendpoint=127.0.0.1:" + itoaPort(sides[i^1].bindPort()) + "\n"
		if err := sides[i].dev.IpcSet(endpointCfg); err != nil {
			t.Fatalf("%s: endpoint IpcSet side %d: %v", cfg.name, i, err)
		}
	}

	// Upstream race workaround (documented, not patched): amneziawg-go's TUN
	// reader snapshots paddings.transport once per read iteration and the
	// routine starts inside NewDevice — an iteration opened before IpcSet
	// merged S-values sends the first packet with a zero padding prefix.
	// Drain that poisoned iteration with an unroutable warmup packet (dst
	// outside the /32 AllowedIPs => dropped at lookup, never transmitted),
	// then give both readers a fresh iteration.
	for i := range sides {
		warm := tuntest.Ping(netip.MustParseAddr("192.0.2.9"), ip4(sides[i].ip))
		sides[i].tun.Outbound <- warm
	}
	time.Sleep(200 * time.Millisecond)
	return sides
}

func sendPing(t *testing.T, from, to *pairSide) {
	t.Helper()
	msg := tuntest.Ping(ip4(to.ip), ip4(from.ip))
	from.tun.Outbound <- msg
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	select {
	case got := <-to.tun.Inbound:
		if !bytes.Equal(msg, got) {
			t.Fatalf("packet transited mangled: %d vs %d bytes", len(got), len(msg))
		}
	case <-timer.C:
		t.Fatal("ping did not transit")
	}
}

func TestInteropChannelVanillaPair(t *testing.T) {
	zero := func() Profile { return Profile{} }
	sides := newInteropPair(t, pairConfig{name: "vanilla<->vanilla", profiles: [2]func() Profile{zero, zero}})
	sendPing(t, sides[0], sides[1])
	sendPing(t, sides[1], sides[0])
}

func TestInteropChannelAWGFullPair(t *testing.T) {
	sides := newInteropPair(t, pairConfig{
		name:     "awg-full<->awg-full",
		profiles: [2]func() Profile{awgFullProfile, awgFullProfile},
	})
	sendPing(t, sides[0], sides[1])
	sendPing(t, sides[1], sides[0])
}

// TestInteropChannelAWGJunkVsVanilla pins the CF-compat shape: a vanilla-safe
// junk profile interoperates with a vanilla device in BOTH directions
// (client-side-only params are dropped by the vanilla peer, research §7.3).
func TestInteropChannelAWGJunkVsVanilla(t *testing.T) {
	zero := func() Profile { return Profile{} }
	sides := newInteropPair(t, pairConfig{
		name:     "awg-junk<->vanilla",
		profiles: [2]func() Profile{junkOnlyProfile, zero},
	})
	sendPing(t, sides[0], sides[1]) // junk initiator -> vanilla responder
	sendPing(t, sides[1], sides[0]) // vanilla initiator -> junk responder
}

// TestInteropRealUDPVanillaPair runs our own Bind over loopback UDP end to end.
func TestInteropRealUDPVanillaPair(t *testing.T) {
	zero := func() Profile { return Profile{} }
	sides := newInteropPair(t, pairConfig{
		name:       "vanilla<->vanilla@udp",
		profiles:   [2]func() Profile{zero, zero},
		useRealUDP: true,
	})
	sendPing(t, sides[0], sides[1])
	sendPing(t, sides[1], sides[0])
}

// TestInteropRealUDPAWGFullPair runs the full AWG parameter set through real
// sockets — the closest CI proxy of the field data plane.
func TestInteropRealUDPAWGFullPair(t *testing.T) {
	sides := newInteropPair(t, pairConfig{
		name:       "awg-full<->awg-full@udp",
		profiles:   [2]func() Profile{awgFullProfile, awgFullProfile},
		useRealUDP: true,
	})
	sendPing(t, sides[0], sides[1])
	sendPing(t, sides[1], sides[0])
}

// TestNetstackHandshakeSmoke gates the userspace netstack TUN mode in CI:
// netstack client + our-bind responder; a TCP dial through the netstack
// queues packets into the tunnel forcing a handshake; success is read from
// the responder's IpcGet last_handshake_time_sec.
func TestNetstackHandshakeSmoke(t *testing.T) {
	privA, privB, pubA, pubB := mustKeys(t)

	respTun := tuntest.NewChannelTUN()
	stopDrain := make(chan struct{})
	defer close(stopDrain)
	go func() {
		for {
			select {
			case <-respTun.Inbound:
			case <-stopDrain:
				return
			}
		}
	}()

	respBindRaw := NewBind(SocketOptions{})
	respDev := device.NewDevice(respTun.TUN(), respBindRaw, DeviceLogger(nil))
	defer respDev.Close()

	respCfg := Config{
		PrivateKey: privB,
		Peers:      []PeerConfig{{PublicKey: pubA}},
	}
	respIPC, err := respCfg.IPCString()
	if err != nil {
		t.Fatal(err)
	}
	if err := respDev.IpcSet(respIPC); err != nil {
		t.Fatalf("responder IpcSet: %v", err)
	}
	if err := respDev.Up(); err != nil {
		t.Fatalf("responder Up: %v", err)
	}
	respPort := respBindRaw.ActualPort()
	if respPort == 0 {
		t.Fatal("responder bind has no port")
	}

	clientTun, ns, err := netstack.CreateNetTUN(
		[]netip.Addr{ip4([4]byte{10, 0, 0, 2})}, nil, DefaultMTU)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	clientBind := NewBind(SocketOptions{})
	clientDev := device.NewDevice(clientTun, clientBind, DeviceLogger(nil))
	defer clientDev.Close()

	clientCfg := Config{
		PrivateKey: privA,
		Peers: []PeerConfig{{
			PublicKey:  pubB,
			Endpoint:   mustAddrPort("127.0.0.1:" + itoaPort(respPort)),
			AllowedIPs: nil,
		}},
	}
	cliIPC, err := clientCfg.IPCString()
	if err != nil {
		t.Fatal(err)
	}
	if err := clientDev.IpcSet(cliIPC); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	// Let the TUN reader cycle past any pre-config iteration (upstream
	// padding-snapshot race; see newInteropPair warmup comment).
	time.Sleep(200 * time.Millisecond)
	go func() { // traffic trigger: any queued packet forces handshake initiation
		_, _ = ns.DialContext(ctx, "tcp", "10.0.0.1:80")
	}()

	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		state, err := respDev.IpcGet()
		if err == nil && strings.Contains(state, "last_handshake_time_sec=") &&
			!strings.Contains(state, "last_handshake_time_sec=0") {
			return // handshake proven through the netstack data plane
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatal("handshake did not complete within deadline")
}

// TestKernelTUNOpenManualGate is NOT part of default CI: /dev/net/tun needs
// --device /dev/net/tun --cap-add NET_ADMIN. It skips everywhere so the
// manual privileged gate can run before a field session.
func TestKernelTUNOpenManualGate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun absent; run with --device /dev/net/tun --cap-add NET_ADMIN")
	}
	tn, err := NewTunnel(TunnelConfig{Mode: ModeKernel, MTU: DefaultMTU})
	if err != nil {
		t.Fatalf("kernel TUN open: %v", err)
	}
	name, err := tn.Device.Name()
	if err != nil || name == "" {
		t.Fatalf("kernel TUN name: %q err=%v", name, err)
	}
	if mtu, err := tn.Device.MTU(); err != nil || mtu != DefaultMTU {
		t.Fatalf("kernel TUN MTU=%d err=%v", mtu, err)
	}
	_ = tn.Device.Close()
}
