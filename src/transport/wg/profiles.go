// Versioned AWG obfuscation-profile catalog (design §3): the same pattern
// as the MASQUE endpoint catalog — a fixed, tested seed set plus explicit
// IDs that seek-ladder configs reference. Families follow the field
// research (§2 zapret-gui matrix, §4 Aether aethernoize, §5 Nova library):
//
//	vanilla-off   no obfuscation at all (classic wireguard peer)
//	quic-*        fake-QUIC Initial junk family (client-side only)
//	sip-*         VoIP INVITE mimicry family (client-side only)
//	crlf-*        CRLF+timestamp+random text family, light/aggressive
//
// Red line §11.4: junk is NEVER enabled against a peer without confirmed
// compatibility. Profiles carry Target so the seeker can filter: cf-warp
// targets may only use the vanilla-safe junk family (S/H untouched — the
// Cloudflare edge accepts nothing else); awg-server targets (plan Б) may
// use S/H-modifying templates once such servers exist in the field.
//
// Seeds are deliberately conservative templates, not claimed byte-exact
// copies of any vendor blob: exact payloads belong to field libraries and
// can be loaded over this schema later.
//
// DEFAULT LADDER POLICY (owner decision 2026-08-24): for cf-warp the
// JUNK FAMILIES GO FIRST and vanilla-off anchors LAST. Rationale: junk is
// confined to the handshake phase (I-packets precede initiation; Jc packets
// interleave around handshake messages; transport data carries no junk), so
// defaulting to junk costs ~nothing in steady state while defeating passive
// WireGuard establishment fingerprinting (148-byte init / type-byte
// signatures) at DPI middleboxes from the very first datagram. The seeker
// escalates DOWN to vanilla-off automatically when a family fails the gate,
// and last-good persists whatever won — the order only sets where we START,
// never where we are FORCED TO STAY.
package transportwg

import (
	"fmt"
	"sort"
)

// CatalogVersion increments on any change to the seed set or the catalog
// schema; trace exports and seek reports carry it for field correlation.
// v2: external field-profile libraries (profiles_loader.go, PATCH-05
// Variant B) join the seed set; the seeds themselves stay template-grade
// fallback (see the honest-posture note in profiles_loader.go).
const CatalogVersion = 2

// catalogEngineGeneration is the DEMON generation the ladder gates against
// (PATCH-17, WG MINOR 12 / design WG4): profiles whose EngineGeneration
// exceeds the current demon are SKIPPED by the ladder (not discarded) and
// re-enter automatically once the daemon is updated. Default 1.
var catalogEngineGeneration = 1

// filterByEngineGeneration returns the templates whose minimum demon
// generation is satisfied by the current demon (PATCH-17). Exported for
// library-merge paths; LadderFor applies it internally.
func filterByEngineGeneration(tpls []ProfileTemplate) []ProfileTemplate {
	out := make([]ProfileTemplate, 0, len(tpls))
	for _, t := range tpls {
		if t.EngineGeneration > catalogEngineGeneration {
			continue
		}
		out = append(out, t)
	}
	return out
}

// ResetEngineGenerationForTest restores the default demon generation (test
// hygiene: SetEngineGeneration leaks across tests otherwise).
func ResetEngineGenerationForTest() { catalogEngineGeneration = 1 }

// EngineGeneration reports the demon generation the ladder gates against.
func EngineGeneration() int { return catalogEngineGeneration }

// SetEngineGeneration updates the demon generation (engine wiring at
// startup/upgrade). Values < 1 are ignored (0 is the "any" profile marker).
func SetEngineGeneration(gen int) {
	if gen >= 1 {
		catalogEngineGeneration = gen
	}
}

// ProfileTarget restricts where a template may be applied.
type ProfileTarget string

const (
	// TargetCfWarp: Cloudflare WARP edge — only client-side junk allowed.
	TargetCfWarp ProfileTarget = "cf-warp"
	// TargetAwgServer: own/AWG server (plan Б) — S/H templates permitted.
	TargetAwgServer ProfileTarget = "awg-server"
)

// ProfileTemplate is one named entry of the catalog.
type ProfileTemplate struct {
	ID      string
	Target  ProfileTarget
	Ports   []uint16 // affinity hint (endpoint port diversification)
	Comment string
	// EngineGeneration is the minimum demon generation this profile requires
	// (PATCH-17): 0 = any demon; 1+ = the profile joins the ladder only when
	// EngineGeneration() >= this value. Skipped profiles re-enter after a
	// daemon upgrade — a soft gate, never a permanent discard.
	EngineGeneration int
	build            func() Profile
}

// Build renders the template into a validated Profile instance.
func (t ProfileTemplate) Build() (Profile, error) {
	p := t.build()
	if err := p.Validate(); err != nil {
		return p, fmt.Errorf("transportwg: catalog profile %s: %w", t.ID, err)
	}
	if t.Target == TargetCfWarp && !p.VanillaSafe() {
		return p, fmt.Errorf("transportwg: catalog profile %s: cf-warp target must be vanilla-safe", t.ID)
	}
	return p, nil
}

// defaultCatalog is the versioned seed set. Order matters only as the
// fallback ladder when no preferred profile exists.
func defaultCatalog() []ProfileTemplate {
	return []ProfileTemplate{
		{
			ID:     "vanilla-off",
			Target: TargetCfWarp,
			Comment: "classic wireguard peer: zero obfuscation parameters; " +
				"the compatibility baseline every candidate must accept",
			build: func() Profile { return Profile{} },
		},
		{
			ID:     "quic-a",
			Target: TargetCfWarp,
			Ports:  []uint16{2408, 500, 1701, 4500},
			Comment: "fake-QUIC Initial junk (Nova v1 lineage): QUIC long-header " +
				"bytes 0xce… + timestamp + tail randomness, jc=4 jmin=40 jmax=70",
			build: func() Profile {
				return Profile{
					JunkCount: 4, JunkMin: 40, JunkMax: 70,
					InitPacket: [5]string{"<b 0xce00000001><t><r 8>"},
				}
			},
		},
		{
			ID:     "quic-b",
			Target: TargetCfWarp,
			Ports:  []uint16{2408, 500, 1701, 4500},
			Comment: "second QUIC Initial variant (Nova v2 lineage, 0xc7 marker) " +
				"with slightly wider junk sizing",
			build: func() Profile {
				return Profile{
					JunkCount: 5, JunkMin: 50, JunkMax: 90,
					InitPacket: [5]string{"<b 0xc700000001><t><rc 10>"},
				}
			},
		},
		{
			ID:     "sip-invite",
			Target: TargetCfWarp,
			Ports:  []uint16{2408, 500, 1701, 4500},
			Comment: "VoIP INVITE mimicry (Nova v3 lineage): ASCII 'INVITE sip:' " +
				"head + random digit tail",
			build: func() Profile {
				return Profile{
					JunkCount: 4, JunkMin: 40, JunkMax: 70,
					InitPacket: [5]string{"<b 0x494e56495445207369703a><rd 12><r 6>"},
				}
			},
		},
		{
			ID:     "crlf-light",
			Target: TargetCfWarp,
			Ports:  []uint16{2408, 500, 1701, 4500, 854, 8886},
			Comment: "Aether aethernoize light: CRLF + timestamp + random chars, " +
				"jc=4 jmin=48 jmax=190",
			build: func() Profile {
				return Profile{
					JunkCount: 4, JunkMin: 48, JunkMax: 190,
					InitPacket: [5]string{"<b 0x0d0a><t><rc 16>"},
				}
			},
		},
		{
			ID:     "crlf-aggressive",
			Target: TargetCfWarp,
			Ports:  []uint16{2408, 500, 1701, 4500, 854, 8886},
			Comment: "Aether aethernoize aggressive: wider junk (jc=10, 80–384) " +
				"plus POST-like i2 payload",
			build: func() Profile {
				return Profile{
					JunkCount: 10, JunkMin: 80, JunkMax: 384,
					InitPacket: [5]string{"<b 0x0d0a><t><r 24>", "<b 0x504f5354202f><rc 12>"},
				}
			},
		},
		{
			ID:     "awg-sh-a",
			Target: TargetAwgServer,
			Comment: "AWG server template (plan Б): S-padding + custom header " +
				"ranges — BOTH-ENDS parameters, never valid against Cloudflare",
			build: func() Profile {
				return Profile{
					JunkCount: 4, JunkMin: 40, JunkMax: 70,
					PadInit:         15,
					PadResponse:     18,
					PadCookie:       20,
					PadTransport:    30,
					HeaderInit:      &Range{123456, 123500},
					HeaderResponse:  &Range{67543, 67550},
					HeaderCookie:    &Range{123123, 123200},
					HeaderTransport: &Range{32345, 32350},
				}
			},
		},
	}
}

// Lookup returns the catalog entry by ID.
func LookupProfile(id string) (ProfileTemplate, error) {
	for _, t := range defaultCatalog() {
		if t.ID == id {
			return t, nil
		}
	}
	return ProfileTemplate{}, fmt.Errorf("transportwg: unknown catalog profile %q", id)
}

// CatalogIDs returns sorted IDs (test/diagnostics helper).
func CatalogIDs() []string {
	ids := make([]string, 0, 8)
	for _, t := range defaultCatalog() {
		ids = append(ids, t.ID)
	}
	sort.Strings(ids)
	return ids
}

// cfWarpLadderOrder is the default cf-warp ladder policy (junk-first,
// owner decision 2026-08-24 — see the package comment for rationale).
var cfWarpLadderOrder = []string{
	"quic-a", "quic-b", "sip-invite", "crlf-light", "crlf-aggressive", "vanilla-off",
}

// LadderFor builds the per-candidate profile order for a target:
// preferred (last-good) first when it exists in the catalog, then the
// DEFAULT LADDER POLICY of the target. For cf-warp that policy is
// JUNK-FIRST (quic → sip → crlf families, vanilla-off LAST as the
// compatibility fallback); for awg-server targets the catalog order applies
// (S/H templates first and only).
func LadderFor(target ProfileTarget, preferredID string) ([]ProfileTemplate, error) {
	var ladder []ProfileTemplate
	push := func(t ProfileTemplate) {
		for _, have := range ladder {
			if have.ID == t.ID {
				return
			}
		}
		// PATCH-17 (WG MINOR 12): a profile whose minimum demon generation
		// exceeds the current demon is SKIPPED (soft gate) — it re-enters
		// the ladder automatically after a daemon upgrade.
		if t.EngineGeneration > catalogEngineGeneration {
			return
		}
		ladder = append(ladder, t)
	}
	if preferredID != "" {
		t, err := LookupProfile(preferredID)
		if err != nil {
			return nil, err
		}
		if t.Target == target {
			push(t)
		}
	}
	pushAll := func(ids []string) error {
		for _, id := range ids {
			t, err := LookupProfile(id)
			if err != nil {
				return err
			}
			if t.Target == target {
				push(t)
			}
		}
		return nil
	}
	switch target {
	case TargetCfWarp:
		if err := pushAll(cfWarpLadderOrder); err != nil {
			return nil, err
		}
	default:
		for _, t := range defaultCatalog() {
			if t.Target == target {
				push(t)
			}
		}
	}
	if len(ladder) == 0 {
		return nil, fmt.Errorf("transportwg: empty ladder for target %q", target)
	}
	return ladder, nil
}
