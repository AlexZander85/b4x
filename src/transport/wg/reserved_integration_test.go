// WG2 integration matrix (design §10): reserved-bytes routing against the
// fake CF edge — happy path proves stamping/scrubbing round-trip; wrong-id
// proves the routing discipline actually keys on reserved bytes; the
// no-flag case pins red line §11.3 (zeros for non-CF peers).
package transportwg

import (
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// edgeKeyPair generates the responder keypair; the client identity must pin
// its public half.
func edgeKeyPair(t *testing.T) (priv, pub Key) {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k, mustPub(t, k)
}

// newWiredClient builds a client device from a wg identity, installing the
// reserved hook iff the identity carries cf_warp. The endpoint is wired by
// WireEndpoint() AFTER Up (same ordering as the WG1 interop harness).
func newWiredClient(t *testing.T, id *Identity) (*device.Device, *tuntest.ChannelTUN, *Bind) {
	t.Helper()
	bind := NewBind(SocketOptions{})
	hook, err := id.DatagramHookOrNil()
	if err != nil {
		t.Fatalf("hook gate: %v", err)
	}
	switch {
	case hook != nil && testing.Verbose():
		bind.SetDatagramHook(chainedDump{t: t, next: hook})
	case hook != nil:
		bind.SetDatagramHook(hook)
	case testing.Verbose():
		bind.SetDatagramHook(chainedDump{t: t})
	}
	tunDev := tuntest.NewChannelTUN()
	cfg := Config{
		PrivateKey: id.PrivateKey,
		Peers: []PeerConfig{{
			PublicKey: id.PeerPublicKey,
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(netip.MustParseAddr("10.9.9.1"), 32), // edge inner IP
			},
		}},
	}
	ipc, err := cfg.IPCString()
	if err != nil {
		t.Fatal(err)
	}
	var dlog *device.Logger
	if testing.Verbose() { // verbose client diagnostics under -v
		dlog = device.NewLogger(device.LogLevelVerbose, "cli: ")
	} else {
		dlog = DeviceLogger(nil)
	}
	dev := device.NewDevice(tunDev.TUN(), bind, dlog)
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}
	return dev, tunDev, bind
}

// WireEndpoint points the client's peer at the edge post-Up.
func WireEndpoint(dev *device.Device, peerPub Key, addr string) error {
	return dev.IpcSet("public_key=" + peerPub.Hex() + "\nendpoint=" + addr + "\n")
}

const (
	clientTunnelIP = "172.16.0.2"
	edgeInnerIP    = "10.9.9.1"
)

func TestFakeEdgeReservedRoutingHappyPath(t *testing.T) {
	clientID := "uS9/" // -> b9 4f 7f
	reserved, err := ReservedFromClientID(clientID)
	if err != nil {
		t.Fatal(err)
	}
	edgePriv, edgePub := edgeKeyPair(t)

	id, err := NewIdentity(mustB64Key(t), edgePub.B64(), clientID, clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}

	edge, err := startFakeEdge(t, reserved, true /*require*/, true /*stamp*/, true /*scrub*/)
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.Configure(edgePriv, mustPub(t, id.PrivateKey), netip.MustParseAddr(clientTunnelIP)); err != nil {
		t.Fatal(err)
	}

	dev, tunDev, _ := newWiredClient(t, id)
	if err := WireEndpoint(dev, id.PeerPublicKey, edge.addr()); err != nil {
		t.Fatal(err)
	}

	// The ping is the handshake trigger (no keepalive configured): it forces
	// initiation immediately after Up.
	msg := tuntest.Ping(netip.MustParseAddr(edgeInnerIP), netip.MustParseAddr(clientTunnelIP))
	tunDev.Outbound <- msg

	waitHandshake(t, edge, 15*time.Second)
	if !waitCondition(5*time.Second, func() bool { return clientHandshakeEstablished(dev) }) {
		t.Fatal("client never completed its side of the handshake")
	}

	// Data plane: the same packet must land on the edge TUN.
	select {
	case <-edge.tun.Inbound:
	case <-time.After(8 * time.Second):
		t.Fatal("data packet did not transit to the fake edge")
	}

	seen, dropped := edge.bind.stats()
	if len(seen) == 0 || dropped != 0 {
		t.Fatalf("edge stats: seen=%d dropped=%d", len(seen), dropped)
	}
	for i, s := range seen {
		if s.Res != reserved {
			t.Fatalf("datagram %d carried reserved %v, want %v (routing broken)", i, s, reserved)
		}
	}
}

func TestFakeEdgeRejectsWrongClientID(t *testing.T) {
	wrongID, rightID := "AAAA", "uS9/" // different identities
	reserved, err := ReservedFromClientID(rightID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ReservedFromClientID(wrongID)
	if err != nil || other == reserved {
		t.Fatalf("fixture ids must differ: %v %v", other, reserved)
	}
	edgePriv, edgePub := edgeKeyPair(t)

	id, err := NewIdentity(mustB64Key(t), edgePub.B64(), wrongID, clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}

	edge, err := startFakeEdge(t, reserved, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.Configure(edgePriv, mustPub(t, id.PrivateKey), netip.MustParseAddr(clientTunnelIP)); err != nil {
		t.Fatal(err)
	}
	clientDev, clientTun, _ := newWiredClient(t, id)
	_ = clientDev
	if err := WireEndpoint(clientDev, id.PeerPublicKey, edge.addr()); err != nil {
		t.Fatal(err)
	}

	// Trigger initiations: the ping is queued and retried by the engine.
	warm := tuntest.Ping(netip.MustParseAddr(edgeInnerIP), netip.MustParseAddr(clientTunnelIP))
	clientTun.Outbound <- warm

	time.Sleep(2500 * time.Millisecond) // several initiation retries

	seen, dropped := edge.bind.stats()
	if dropped == 0 || len(seen) == 0 {
		t.Fatalf("routing discipline not exercised: seen=%d dropped=%d", len(seen), dropped)
	}
	for i, s := range seen {
		if s.Res == reserved {
			t.Fatalf("datagram %d matched foreign expected id — fixture broken", i)
		}
	}
	if edge.handshakeEstablished() {
		t.Fatal("handshake must NOT complete when routing rejects the identity")
	}
}

// TestGenericAWGServerSeesZerosWithoutCFFlag pins red line §11.3 on the wire:
// cf_warp=false => hook absent => every datagram carries zeroed reserved.
func TestGenericAWGServerSeesZerosWithoutCFFlag(t *testing.T) {
	var zeros [3]byte
	edgePriv, edgePub := edgeKeyPair(t)

	id, err := NewIdentity(mustB64Key(t), edgePub.B64(), "uS9/", clientTunnelIP, "", false)
	if err != nil {
		t.Fatal(err)
	}

	edge, err := startFakeEdge(t, zeros, false /*require: generic server*/, false /*stampTX*/, false /*scrub*/)
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.Configure(edgePriv, mustPub(t, id.PrivateKey), netip.MustParseAddr(clientTunnelIP)); err != nil {
		t.Fatal(err)
	}
	clientDev, clientTun, _ := newWiredClient(t, id)
	_ = clientDev
	if err := WireEndpoint(clientDev, id.PeerPublicKey, edge.addr()); err != nil {
		t.Fatal(err)
	}

	// Trigger initiations: any queued packet forces the handshake.
	clientTun.Outbound <- tuntest.Ping(netip.MustParseAddr(edgeInnerIP), netip.MustParseAddr(clientTunnelIP))

	waitHandshake(t, edge, 15*time.Second)

	seen, dropped := edge.bind.stats()
	if len(seen) == 0 || dropped != 0 {
		t.Fatalf("edge stats: seen=%d dropped=%d", len(seen), dropped)
	}
	for i, s := range seen {
		if s.Res != zeros {
			t.Fatalf("datagram %d carried reserved %v without cf_warp — red line §11.3 violated", i, s)
		}
	}
}
