package managed

import (
	"net"
	"testing"
)

func TestAllocateLoopbackPortWasAvailableForTCPAndUDP(t *testing.T) {
	addr, err := AllocateLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("allocated TCP port not reusable: %v", err)
	}
	defer tcpListener.Close()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("allocated UDP port not reusable: %v", err)
	}
	defer udpListener.Close()
}
