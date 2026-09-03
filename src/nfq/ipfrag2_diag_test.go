package nfq

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/sock"
)

func TestBuildIPFragmentsV4Geometry(t *testing.T) {
	raw, _ := steerFixturePacket(t, echCHPayload(true, 1802))
	pi, ok := ExtractPacketInfoV4(raw)
	if !ok {
		t.Fatal("extract")
	}

	f1, f2, ok := buildIPFragmentsV4(raw)
	if !ok {
		t.Fatal("fragmentation rejected a valid packet")
	}

	id := binary.BigEndian.Uint16(raw[4:6])
	for name, f := range map[string][]byte{"f1": f1, "f2": f2} {
		if got := binary.BigEndian.Uint16(f[4:6]); got != id {
			t.Fatalf("%s IP ID %d != original %d", name, got, id)
		}
		if ff := binary.BigEndian.Uint16(f[6:8]); ff&0x4000 != 0 {
			t.Fatalf("%s must clear DF (DF+MF is illegal)", name)
		}
		if want := uint16(len(f)); binary.BigEndian.Uint16(f[2:4]) != want {
			t.Fatalf("%s total_len mismatch: %d vs %d", name, binary.BigEndian.Uint16(f[2:4]), want)
		}
	}

	ff1 := binary.BigEndian.Uint16(f1[6:8])
	if ff1&0x2000 == 0 || ff1&0x1FFF != 0 {
		t.Fatalf("f1 flags/offset %#x: MF set, offset 0 required", ff1)
	}
	ff2 := binary.BigEndian.Uint16(f2[6:8])
	if ff2&0x2000 != 0 {
		t.Fatalf("f2 must clear MF: %#x", ff2)
	}
	k := int(ff2&0x1FFF) * 8
	if k == 0 || k%8 != 0 {
		t.Fatalf("continuation offset %d not 8-aligned/nonzero", k)
	}
	if k <= pi.TCPHdrLen {
		t.Fatalf("split %d must sit beyond the TCP header (%d)", k, pi.TCPHdrLen)
	}

	// TCP header fully inside the head fragment.
	if len(f1) < pi.IPHdrLen+pi.TCPHdrLen {
		t.Fatal("TCP header does not fit into fragment 1")
	}

	// L4 union reassembles to the original segment.
	var l4 bytes.Buffer
	l4.Write(f1[pi.IPHdrLen:])
	l4.Write(f2[pi.IPHdrLen:])
	if !bytes.Equal(l4.Bytes(), raw[pi.IPHdrLen:]) {
		t.Fatal("L4 bytes mutated by fragmentation")
	}
}

func TestBuildIPFragmentsChecksumsValid(t *testing.T) {
	raw, _ := steerFixturePacket(t, echCHPayload(true, 1802))
	f1, f2, ok := buildIPFragmentsV4(raw)
	if !ok {
		t.Fatal("rejected")
	}
	for name, f := range map[string][]byte{"f1": f1, "f2": f2} {
		ihl := int(f[0]&0x0F) * 4
		recomputed := append([]byte(nil), f[:ihl]...)
		sock.FixIPv4Checksum(recomputed) // idempotent when checksum is correct
		if !bytes.Equal(recomputed, f[:ihl]) {
			t.Fatalf("%s IPv4 header checksum invalid", name)
		}
	}
}

func TestBuildIPFragmentsRejectsTiny(t *testing.T) {
	raw, _ := steerFixturePacket(t, []byte{0x16, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5})
	if _, _, ok := buildIPFragmentsV4(raw); ok {
		t.Fatal("10-byte L4 payload must be rejected")
	}
}

func TestMaybeIPFrag2DiagnoseGuards(t *testing.T) {
	video := steerVideoSet()
	ui := &config.SetConfig{Name: "youtube-ui"}
	w := newSteerTestWorker()

	raw, pkt := steerFixturePacket(t, echCHPayload(true, 1802))
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	if got := w.maybeIPFrag2Diagnose(vc, pkt, video, raw, false); got != ipfragDiagEnabled {
		t.Fatalf("consumed=%v, want %v (compile-time gate)", got, ipfragDiagEnabled)
	}
	if ipfragDiagEnabled && vc.verdict != engine.VerdictDrop {
		t.Fatalf("verdict=%v, want drop when consumed", vc.verdict)
	}

	vcUI := &verdictCtx{verdict: engine.VerdictAccept}
	if w.maybeIPFrag2Diagnose(vcUI, pkt, ui, raw, false) && ipfragDiagEnabled {
		t.Fatal("youtube-ui set must never be consumed")
	}

	rawClean, pktClean := steerFixturePacket(t, echCHPayload(false, 776))
	vcClean := &verdictCtx{verdict: engine.VerdictAccept}
	if w.maybeIPFrag2Diagnose(vcClean, pktClean, video, rawClean, false) && ipfragDiagEnabled {
		t.Fatal("ECH-free CH must keep the regular inject path")
	}
}

func TestSteerGateMatchesDiagnosticBuilds(t *testing.T) {
	if steerECHEnabled == (tlsrecDiagEnabled || ipfragDiagEnabled || quicboundEnabled || quicSynRstEnabled || l5PPEEnabled || echFlowEnabled || ggcDiscEnabled || qbpEnabled || vnbEnabled || ja4Enabled || stormEnabled) {
		t.Fatal("steerECHEnabled must be off in any diagnostic build")
	}
}
