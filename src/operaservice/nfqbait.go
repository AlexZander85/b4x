// NFQ bait handle (review E-OPERA §7.4.3, stage OP-M3): when
// masquerade.ttl_fake is enabled, the transport's own egress sockets are
// SO_MARKed (packetmark.MarkOperaEgress) and an OUTPUT mangle rule routes
// the marked packets into the existing action queue, where the standard
// fakedsplit/fakeddisorder strategies apply the fake first-flight with the
// low-TTL fake ClientHello — the amnezia-I1 semantics ported to TCP.
//
// This file owns the DECISION seam (honest status): the tables-layer rule
// management and the socket marking land with OP-M3; until the rule is
// confirmed applied by the tables layer, the bait reports inactive so the
// status never lies about an enforcement that is not happening.
package operaservice

// nfwBaitState is the current handle: nil means "not configured";
// configured-but-inactive means the OUTPUT rule is absent (tables failure,
// NFQ engine off) and the status must say so.
type nfwBaitState struct {
	configured bool
	active     bool
}

func (s *nfwBaitState) Active() bool { return s != nil && s.active }

// SetActive records the tables-layer confirmation (called by the daemon
// after tables.ApplyOperaBaitOnly succeeded / on teardown).
func (s *nfwBaitState) SetActive(active bool) {
	if s == nil {
		return
	}
	s.active = active
}

// newNFWBaitIfConfigured builds the handle when the bait is configured;
// the ACTIVE flag flips only after the tables layer confirms the OUTPUT
// rule (honest status — review §7.8.5).
func newNFWBaitIfConfigured(ttlFake bool) NFWBait {
	if !ttlFake {
		return nil
	}
	return &nfwBaitState{configured: true}
}
