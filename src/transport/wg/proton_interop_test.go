package transportwg

import (
	"encoding/hex"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// protonQuicHexStub is a fixed 1250-byte QUIC-Initial-shaped blob (long
// header 0xC0, v1, DCIL=8/SCIL=0, 8-byte DCID, deterministic tail) — the
// wire-shape stand-in for the runtime generator, whose full RFC 9001
// decryptability is golden-tested in transport/proton. Here the assertion
// is ENGINE tolerance: the 1250-byte I1 element survives the chain parser
// and the vanilla peer tolerates the extra datagrams.
var protonQuicHexStub = func() string {
	buf := make([]byte, 1250)
	buf[0] = 0xC0
	buf[1], buf[2], buf[3], buf[4] = 0x00, 0x00, 0x00, 0x01
	buf[5] = 0x80
	for i := 6; i < len(buf); i++ {
		buf[i] = byte(i * 7)
	}
	return hex.EncodeToString(buf)
}()

// ---- E-PROTON interop (patch-plan §5.5): AWG(proton-quic) <-> vanilla WG ----

// protonQuicProfile is the proton-quic shape WITH a runtime I1 (what the
// service fills before IpcSet): a 1250-byte QUIC Initial blob + Jc=3 junk.
func protonQuicProfile() Profile {
	return Profile{
		JunkCount: 3, JunkMin: 1, JunkMax: 3,
		InitPacket: [5]string{"<b 0x" + protonQuicHexStub + ">"},
	}
}

// TestInteropChannelProtonQuicVsVanilla pins the E-PROTON data-plane
// contract: the proton-quic profile (I1 blob + junk prefix) interoperates
// with a VANILLA peer in both directions — the vanilla edge drops the I1
// and the junk datagrams, the WG handshake and transport stay
// wire-standard (design §3.1: obfuscation only "in front of the flow").
func TestInteropChannelProtonQuicVsVanilla(t *testing.T) {
	zero := func() Profile { return Profile{} }
	sides := newInteropPair(t, pairConfig{
		name:     "proton-quic<->vanilla",
		profiles: [2]func() Profile{protonQuicProfile, zero},
	})
	sendPing(t, sides[0], sides[1]) // proton-quic initiator -> vanilla responder
	sendPing(t, sides[1], sides[0]) // vanilla initiator -> proton-quic responder
}

// TestInteropRealUDPProtonQuicVsVanilla runs the same shape over real
// loopback UDP sockets (the closest CI proxy of the Proton path).
func TestInteropRealUDPProtonQuicVsVanilla(t *testing.T) {
	zero := func() Profile { return Profile{} }
	sides := newInteropPair(t, pairConfig{
		name:       "proton-quic<->vanilla@udp",
		profiles:   [2]func() Profile{protonQuicProfile, zero},
		useRealUDP: true,
	})
	sendPing(t, sides[0], sides[1])
	sendPing(t, sides[1], sides[0])
}

// TestProtonCatalogVanillaSafe is the acceptance checklist item: Build()
// must accept every proton-family template and the proton-quic I1 chain
// must survive the hard chain parser (the 1250-byte element fits).
func TestProtonCatalogVanillaSafe(t *testing.T) {
	for _, id := range []string{"proton-quic", "proton-vanilla", "proton-sip", "proton-crlf"} {
		tpl, err := LookupProfile(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		p, err := tpl.Build()
		if err != nil {
			t.Fatalf("%s: build: %v", id, err)
		}
		if !p.VanillaSafe() {
			t.Fatalf("%s: must be vanilla-safe", id)
		}
		if id == "proton-quic" && !tpl.RuntimeI1 {
			t.Fatal("proton-quic must be flagged RuntimeI1")
		}
	}
}

// ---- CandidateSource gate (patch-plan §5.4) ----------------------------------------

// TestSeekerCandidateSourceGate verifies the parameterized candidate gate:
// a proton-style source admits its own node list and rejects everything
// else; nil keeps the historical CF-catalog gate byte-for-byte.
func TestSeekerCandidateSourceGate(t *testing.T) {
	base := SessionConfig{} // orderedCandidates never touches the session
	cfPool := netip.MustParseAddrPort("162.159.193.5:2408")
	protonNode := netip.MustParseAddrPort("185.107.56.235:443")
	rogue := netip.MustParseAddrPort("127.0.0.1:51820")
	protonSource := CatalogSourceFunc(func(c netip.AddrPort) bool {
		return c == protonNode
	})

	build := func(src CandidateSource, allow bool) *Seeker {
		cfg := SeekerConfig{
			Base:              base,
			Candidates:        []netip.AddrPort{protonNode, cfPool},
			Target:            TargetProton,
			LadderIDs:         []string{"proton-vanilla"},
			Source:            src,
			AllowOutOfCatalog: allow,
		}
		cfg.fillDefaults()
		return &Seeker{cfg: cfg, strikes: NewStrikeState()}
	}

	// Proton source: only the wired node list passes (CF ranges included).
	got := build(protonSource, false).orderedCandidates(time.Now())
	if len(got) != 1 || got[0] != protonNode {
		t.Fatalf("proton source gate: %v", got)
	}
	// Proton source: the last-good binding honors only in-catalog entries.
	lg := &MemoryLastGood{}
	_ = lg.Put(Attempt{Endpoint: cfPool, ProfileID: "proton-vanilla", At: time.Now()})
	cfg := SeekerConfig{
		Base: base, Candidates: []netip.AddrPort{protonNode}, Target: TargetProton,
		LadderIDs: []string{"proton-vanilla"}, Source: protonSource, Store: lg,
	}
	cfg.fillDefaults()
	got = (&Seeker{cfg: cfg, strikes: NewStrikeState()}).orderedCandidates(time.Now())
	if len(got) != 1 || got[0] != protonNode {
		t.Fatalf("out-of-list last-good must drop: %v", got)
	}

	// nil Source keeps the CF-catalog behavior: the Proton node is foreign.
	got = build(nil, false).orderedCandidates(time.Now())
	if len(got) != 1 || got[0] != cfPool {
		t.Fatalf("legacy CF gate broken: %v", got)
	}
	// Tests-only escape still overrides everything; a rogue endpoint rides
	// only through this escape.
	rogueSeen := build(protonSource, true)
	rogueSeen.cfg.Candidates = append(rogueSeen.cfg.Candidates, rogue)
	got = rogueSeen.orderedCandidates(time.Now())
	if len(got) != 3 || !slices.Contains(got, rogue) {
		t.Fatalf("tests escape broken: %v", got)
	}
}
