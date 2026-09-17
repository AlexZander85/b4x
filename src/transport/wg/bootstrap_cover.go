// AWG bootstrap cover (bd b4x-b7n): a fake-QUIC Initial in front of the
// WireGuard initiation — the Nova fakex6-quic pattern.
//
// The catalog entry cf-quic-cover is flagged RuntimeI1: its I1..I5 blob is
// generated at runtime (never stored in the tree). Every consumer that
// materializes an AWG profile MUST fill the slots before IpcSet — the
// vendored device ships only slots that already carry a chain (send.go), so
// an unfilled runtime-I1 profile degenerates to jc=0 + no chain, i.e. VANILLA
// WireGuard with no obfuscation at all. That silent half-state is exactly what
// this file exists to prevent (the proton path learned it the same way).
package transportwg

import (
	"fmt"

	quici1 "github.com/daniellavrushin/b4/transport/quici1"
)

// BootstrapCoverSlots is how many I-slots the fake-QUIC bootstrap cover
// occupies. Nova ships the fake with --dpi-desync-repeats=6; the vendored
// device exposes five I-slots (i1..i5), all sent before the real initiation.
const BootstrapCoverSlots = 5

// RuntimeI1Required reports whether the catalog entry selected for target
// (the preferred id, or the ladder head when id is empty) fills its I1 chain
// at runtime (ProfileTemplate.RuntimeI1). Session builders MUST fill
// Profile.InitPacket before IpcSet for such entries.
func RuntimeI1Required(target ProfileTarget, id string) (bool, error) {
	if id != "" {
		tpl, err := LookupProfile(id)
		if err != nil {
			return false, err
		}
		if tpl.Target != target {
			return false, fmt.Errorf("transportwg: profile %q target %q is not %q", id, tpl.Target, target)
		}
		return tpl.RuntimeI1, nil
	}
	ladder, err := LadderFor(target, "")
	if err != nil {
		return false, err
	}
	return ladder[0].RuntimeI1, nil
}

// FillBootstrapCover fills the I1..I5 slots of a runtime-I1 profile with a
// fresh REAL QUIC v1 Initial (quici1.Build, RFC 9000 sec 14, ~1250 B) so a
// first-flow DPI read sees QUIC before the WireGuard initiation signature
// (Nova fakex6-quic parity). One blob is rendered per call and repeated
// across the slots — the fake-bin repeats pattern. A failed render (empty or
// oversized cover SNI) and a non-runtime-I1 profile are honest no-ops: no
// cover is better than a broken chain, and callers re-Validate afterwards.
func FillBootstrapCover(p Profile, runtimeI1 bool, coverSNI string) Profile {
	if !runtimeI1 {
		return p
	}
	i1 := quici1.Build(coverSNI, nil)
	if i1 == "" {
		return p
	}
	for i := 0; i < BootstrapCoverSlots; i++ {
		p.InitPacket[i] = i1
	}
	return p
}
