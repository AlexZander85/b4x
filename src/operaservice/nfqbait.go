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

// nfwBaitState is the current handle: a nil state means "not configured";
// configured-but-inactive means the rule is absent (NFQ engine off, tables
// failure) and the status must say so.
type nfwBaitState struct {
	configured bool
	active     bool
}

func (s *nfwBaitState) Active() bool { return s != nil && s.active }

// newNFWBaitIfConfigured evaluates the bait activation; the OP-M3 stage
// wires the tables-layer rule + SO_MARK dialer control here. Until then
// the honest answer is nil (not configured) — the TTLFakeActive status
// field stays false and the masquerade ladder treats the bait as the
// orthogonal layer it is (§7.5).
func newNFWBaitIfConfigured(ttlFake bool) NFWBait {
	if !ttlFake {
		return nil
	}
	// OP-M3 will return an active handle once the OUTPUT rule and the
	// socket marking are confirmed applied; the placeholder stays inactive.
	return &nfwBaitState{configured: true, active: false}
}
