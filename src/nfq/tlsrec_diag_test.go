package nfq

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/sni"
)

// Tests are build-agnostic: expectations follow tlsrecDiagEnabled so both
// default and -tags tlsrcediag builds validate their own compiled behavior.

func TestFindECHExtensionOffset(t *testing.T) {
	ch := echCHPayload(true, 1802)
	off := findECHExtensionOffset(ch)
	if off < 14 || off >= len(ch)-4 {
		t.Fatalf("ech offset %d out of sane bounds for %d B CH", off, len(ch))
	}
	if et := binary.BigEndian.Uint16(ch[off : off+2]); et != 0xfe0d {
		t.Fatalf("ext type at offset %d = %#x, want 0xfe0d", off, et)
	}
	if findECHExtensionOffset(echCHPayload(false, 776)) != -1 {
		t.Fatal("ECH-free CH must report no ECH offset")
	}
	for _, bad := range [][]byte{nil, {0x16}, []byte{0x17, 3, 3, 0, 4, 1}} {
		if findECHExtensionOffset(bad) != -1 {
			t.Fatalf("malformed input % x must return -1", bad)
		}
	}
}

func TestReframeTLSRecordAtPreservesBytes(t *testing.T) {
	ch := echCHPayload(true, 1802)
	split := findECHExtensionOffset(ch)

	reframed, ok := reframeTLSRecordAt(ch, split)
	if !ok {
		t.Fatal("valid split rejected")
	}
	if len(reframed) != len(ch)+5 {
		t.Fatalf("reframed len %d, want orig %d + 5 framing bytes", len(reframed), len(ch))
	}

	lenA := int(reframed[3])<<8 | int(reframed[4])
	if reframed[0] != 0x16 || lenA != split-5 {
		t.Fatalf("record A: type=%#x len=%d, want 0x16/%d", reframed[0], lenA, split-5)
	}
	hdrB := reframed[split : split+5]
	lenB := int(hdrB[3])<<8 | int(hdrB[4])
	if hdrB[0] != ch[0] || hdrB[1] != ch[1] || hdrB[2] != ch[2] {
		t.Fatalf("record B type/version % x differs from original % x", hdrB[:3], ch[:3])
	}
	if lenB != len(ch)-split {
		t.Fatalf("record B len %d, want %d", lenB, len(ch)-split)
	}
	if 5+lenA != split || split+5+lenB != len(reframed) {
		t.Fatal("records do not tile the reframed buffer exactly")
	}

	union := append([]byte(nil), reframed[5:split]...)
	union = append(union, reframed[split+5:]...)
	if !bytes.Equal(union, ch[5:]) {
		t.Fatal("handshake bytes mutated by reframing")
	}

	// The whole point of the probe: a single-record parser walking record A
	// no longer reaches the ECH extension.
	metaA := sni.ParseTLSClientHelloMetadata(reframed[:split])
	if metaA.ECHPresent {
		t.Fatal("record A alone must not expose ECH")
	}
}

func TestReframeRejectsBadSplit(t *testing.T) {
	ch := echCHPayload(true, 300)
	for _, at := range []int{-1, 0, 5, len(ch)} {
		if _, ok := reframeTLSRecordAt(ch, at); ok {
			t.Fatalf("split at %d must be rejected", at)
		}
	}
}

func TestMaybeTLSRecDiagnoseGuards(t *testing.T) {
	video := steerVideoSet()
	ui := &config.SetConfig{Name: "youtube-ui"}
	w := newSteerTestWorker()

	raw, pkt := steerFixturePacket(t, echCHPayload(true, 1802))
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	if got := w.maybeTLSRecDiagnose(vc, pkt, video, raw, false); got != tlsrecDiagEnabled {
		t.Fatalf("consumed=%v, want %v (compile-time gate)", got, tlsrecDiagEnabled)
	}
	if tlsrecDiagEnabled && vc.verdict != engine.VerdictDrop {
		t.Fatalf("verdict=%v, want drop when consumed", vc.verdict)
	}

	vcUI := &verdictCtx{verdict: engine.VerdictAccept}
	if w.maybeTLSRecDiagnose(vcUI, pkt, ui, raw, false) {
		t.Fatal("youtube-ui set must never be consumed by tlsrec-diag")
	}

	rawClean, pktClean := steerFixturePacket(t, echCHPayload(false, 776))
	vcClean := &verdictCtx{verdict: engine.VerdictAccept}
	if w.maybeTLSRecDiagnose(vcClean, pktClean, video, rawClean, false) && tlsrecDiagEnabled {
		t.Fatal("ECH-free CH must keep the regular inject path")
	}
}
