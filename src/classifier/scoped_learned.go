package classifier

import (
	"net/netip"
	"strings"
	"time"
)

type ScopedLearnedObservation struct {
	Client        ClientKey
	DestinationIP netip.Addr
	L4Proto       uint8
	Domain        string
	SetID         string
	Source        EvidenceSource
	Confidence    uint8
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConfigGen     uint64
}

func (o ScopedLearnedObservation) Evidence() Evidence {
	return Evidence{
		Source: EvidenceScopedLearnedObservation, Client: o.Client, DestinationIP: o.DestinationIP,
		L4Proto: o.L4Proto, Domain: strings.ToLower(strings.TrimSpace(o.Domain)), SetID: strings.TrimSpace(o.SetID),
		Confidence: o.Confidence, CreatedAt: o.CreatedAt, ExpiresAt: o.ExpiresAt, ConfigGen: o.ConfigGen,
		DomainEvidence: false, Reason: "source-scoped learned observation from " + o.Source.String(),
	}
}
