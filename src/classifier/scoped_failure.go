package classifier

import "net/netip"

type ScopedFailureKey struct {
	Client          ClientKey
	DestinationIP   netip.Addr
	DestinationPort uint16
	L4Proto         uint8
	SetID           string
	DomainKey       string
	ConfigGen       uint64
}

type ScopedEscalationKey struct {
	Client    ClientKey
	DomainKey string
	SetID     string
	ConfigGen uint64
}
