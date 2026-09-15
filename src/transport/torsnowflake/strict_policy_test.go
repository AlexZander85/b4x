package torsnowflake

import (
	"context"
	"errors"
	"net"
	"testing"

	sflib "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"

	"github.com/daniellavrushin/b4/transport/tor"
)

func TestPinnedCarrierRefusesDirectSnowflakeUDP(t *testing.T) {
	p := &protectedPionNet{allowDirectPacket: false}
	w := &wrappedPionNet{prot: p}
	raddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3478}
	if _, err := w.DialUDP("udp", nil, raddr); !errors.Is(err, ErrPacketCarrierRequired) {
		t.Fatalf("DialUDP err=%v, want ErrPacketCarrierRequired", err)
	}
	if _, err := w.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}); !errors.Is(err, ErrPacketCarrierRequired) {
		t.Fatalf("ListenUDP err=%v, want ErrPacketCarrierRequired", err)
	}
	if _, err := w.ListenPacket("udp", "127.0.0.1:0"); !errors.Is(err, ErrPacketCarrierRequired) {
		t.Fatalf("ListenPacket err=%v, want ErrPacketCarrierRequired", err)
	}
}

func TestSnowflakeBrokerUsesActivePTRendezvousClass(t *testing.T) {
	wantErr := errors.New("stop after class capture")
	var got tor.ConnClass
	NewSnowflakeAdapterPolicy(func(ctx context.Context, class tor.ConnClass, host string, port uint16) (net.Conn, error) {
		got = class
		return nil, wantErr
	}, nil, false)
	if sflib.BrokerDialContext == nil {
		t.Fatal("BrokerDialContext hook missing")
	}
	_, err := sflib.BrokerDialContext(context.Background(), "tcp", "127.0.0.1:443")
	if !errors.Is(err, wantErr) {
		t.Fatalf("broker dial err=%v", err)
	}
	if got != tor.ClassPTRendezvous {
		t.Fatalf("class=%q, want %q", got, tor.ClassPTRendezvous)
	}
}
