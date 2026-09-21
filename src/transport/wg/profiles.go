// Versioned AWG obfuscation-profile catalog (design §3): the same pattern
// as the MASQUE endpoint catalog — a fixed, tested seed set plus explicit
// IDs that seek-ladder configs reference. Families follow the field
// research (§2 zapret-gui matrix, §4 Aether aethernoize, §5 Nova library):
//
//      vanilla-off   no obfuscation at all (classic wireguard peer)
//      quic-*        fake-QUIC Initial junk family (client-side only)
//      sip-*         VoIP INVITE mimicry family (client-side only)
//      crlf-*        CRLF+timestamp+random text family, light/aggressive
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
        "hash/fnv"
        mrand "math/rand/v2"
        "net/netip"
        "sort"
)

// CatalogVersion increments on any change to the seed set or the catalog
// schema; trace exports and seek reports carry it for field correlation.
// v2: external field-profile libraries (profiles_loader.go, PATCH-05
// Variant B) join the seed set; the seeds themselves stay template-grade
// fallback (see the honest-posture note in profiles_loader.go).
// v3: external field-profile libraries can ingest the AWG 3.1 UAPI fields
// already supported by Profile and the IPC bridge.
const CatalogVersion = 3

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
        // TargetProton: Proton VPN free edge — a VANILLA WireGuard peer
        // (E-PROTON design §3.1): the same vanilla-safe invariant as cf-warp
        // applies, and the whole proton family lives in its own catalog entries
        // so the CF ladder never picks up a Proton-shaped payload.
        TargetProton ProfileTarget = "proton"
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
        // RuntimeI1 marks templates whose I1 is generated AT RUNTIME (the
        // E-PROTON proton-quic family): the catalog stores an empty I1 plus this
        // flag; the service fills Profile.InitPacket[0] via the proton QUIC
        // Initial generator before IpcSet (design §3.4). Build() tolerates the
        // empty I1 on such templates — vanilla profiles have empty I-chains too.
        RuntimeI1 bool
        // FieldLibrary marks templates loaded from an external field library
        // (profiles_loader.go): their junk triple is part of a MEASURED shape —
        // per-endpoint diversification (DiversifyJunkFor) must never touch them.
        FieldLibrary bool
        build        func() Profile
}

// Build renders the template into a validated Profile instance.
func (t ProfileTemplate) Build() (Profile, error) {
        p := t.build()
        if err := p.Validate(); err != nil {
                return p, fmt.Errorf("transportwg: catalog profile %s: %w", t.ID, err)
        }
        if (t.Target == TargetCfWarp || t.Target == TargetProton) && !p.VanillaSafe() {
                return p, fmt.Errorf("transportwg: catalog profile %s: %s target must be vanilla-safe", t.ID, t.Target)
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
                        ID:     "cf-field-i1-j4",
                        Target: TargetCfWarp,
                        Ports:  []uint16{443, 500, 1701, 4500},
                        Comment: "measured CF WARP QUIC-Initial bait (44d0 marker, 1250 B): " +
                                "the field blob proven to carry bulk through TSPU (bd b4x-joh)",
                        build: func() Profile {
                                return Profile{
                                        JunkCount: 4, JunkMin: 40, JunkMax: 70,
                                        InitPacket: [5]string{"<b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>"},
                                }
                        },
                },
                {
                        ID:     "cf-field-i1",
                        Target: TargetCfWarp,
                        Ports:  []uint16{443, 500, 1701, 4500},
                        Comment: "measured CF WARP QUIC-Initial bait (44d0 marker, 1250 B): " +
                                "the field blob proven to carry bulk through TSPU (bd b4x-joh)",
                        build: func() Profile {
                                return Profile{
                                        InitPacket: [5]string{"<b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>"},
                                }
                        },
                },
                {
                        ID:        "cf-quic-cover",
                        Target:    TargetCfWarp,
                        Ports:     []uint16{443, 500, 1701, 4500},
                        RuntimeI1: true,
                        Comment: "AWG bootstrap cover (Nova fakex6-quic parity): the I1..I5 " +
                                "slots carry a REAL QUIC v1 Initial (RFC 9000 sec 14, ~1250 B) " +
                                "with a benign cover SNI, so a first-flow DPI read sees QUIC " +
                                "before the WireGuard initiation signature. The blob is " +
                                "generated at runtime (quici1.Build) and repeated across every " +
                                "slot - the Nova fake-bin repeats pattern. Jc=0 keeps the " +
                                "Initial the FIRST datagram. OPT-IN: not in the default " +
                                "cf-warp ladder; pin it via system.warp.awg.profile.",
                        build: func() Profile { return Profile{} },
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

                // ---- E-PROTON family (design §3.2): vanilla WireGuard peers, so every
                // entry is vanilla-safe; the junk is confined "in front of the flow"
                // (I1 + Jc). Ports = the vanilla catalog the free edge listens on
                // (clientconfig [443,88,1224,51820,500,4500]).
                {
                        ID:        "proton-quic",
                        Target:    TargetProton,
                        Ports:     []uint16{443, 88, 1224, 51820, 500, 4500},
                        RuntimeI1: true,
                        Comment: "PREFERRED Proton family (live-verified Nova lineage): a REAL " +
                                "QUIC v1 Initial (RFC 9001, 1250 B) generated at runtime from the " +
                                "SNI pool + plausible 40..70 B junk (Jc=4). FIELD 2026-09-20: the " +
                                "review-P4 Jc=0 shape was dropped by the network while the " +
                                "reference client (Nova/wireproxy-awg) always sends I1 + junk and " +
                                "completes; the catalog keeps the I1 empty — the service fills " +
                                "InitPacket[0] before IpcSet",
                        build: func() Profile {
                                return Profile{
                                        JunkCount: 4, JunkMin: 40, JunkMax: 70,
                                        // I1 arrives at runtime (RuntimeI1); empty here is valid.
                                }
                        },
                },
                {
                        ID:        "proton-quic-j40",
                        Target:    TargetProton,
                        Ports:     []uint16{443, 88, 1224, 51820, 500, 4500},
                        RuntimeI1: true,
                        Comment: "EXPERIMENTAL Proton rung for field trials (review P4): the same " +
                                "runtime QUIC Initial + plausible-size junk (jc=4, 40..70 B — the " +
                                "quic-a neighborhood, 'short QUIC frames'), never the 1..3 B " +
                                "Amnezia-site defaults. NOT in the default ladder; pin it via " +
                                "obfuscation.preferred_profile",
                        build: func() Profile {
                                return Profile{
                                        JunkCount: 4, JunkMin: 40, JunkMax: 70,
                                }
                        },
                },
                {
                        ID:     "proton-vanilla",
                        Target: TargetProton,
                        Ports:  []uint16{443, 88, 1224, 51820, 500, 4500},
                        Comment: "pure vanilla WG peer shape: zero obfuscation — the last " +
                                "Proton ladder step (plain WireGuard fingerprint)",
                        build: func() Profile { return Profile{} },
                },
                {
                        ID:     "proton-sip",
                        Target: TargetProton,
                        Ports:  []uint16{443, 88, 1224, 51820, 500, 4500},
                        Comment: "SIP mimicry (warp-seed lineage): INVITE-head i1 of 348 B " +
                                "and SIP/2.0-head i2 of 245 B, fixed-size random tails",
                        build: func() Profile {
                                // i1: "INVITE sip:" (11 B) + 337 random = 348 B.
                                // i2: "SIP/2.0 " (8 B) + 237 random = 245 B.
                                return Profile{
                                        JunkCount: 4, JunkMin: 40, JunkMax: 70,
                                        InitPacket: [5]string{
                                                "<b 0x494e56495445207369703a><r 337>",
                                                "<b 0x5349502f322e3020><r 237>",
                                        },
                                }
                        },
                },
                {
                        ID:     "proton-crlf",
                        Target: TargetProton,
                        Ports:  []uint16{443, 88, 1224, 51820, 500, 4500},
                        Comment: "crlf-light shape retargeted to Proton (a separate catalog " +
                                "entry — the CF crlf-* records stay untouched)",
                        build: func() Profile {
                                return Profile{
                                        JunkCount: 4, JunkMin: 48, JunkMax: 190,
                                        InitPacket: [5]string{"<b 0x0d0a><t><rc 16>"},
                                }
                        },
                },
        }
}

// DefaultJunkActiveCfWarp returns the first cf-warp ladder profile with an
// ACTIVE junk family (JunkCount > 0), plus its id. The awg+awg outer layer
// requires junk (ErrOuterObfRequired) even though the plain cf-warp ladder
// now leads with vanilla-off (FIELD 2026-09-18: junk breaks the WARP data
// path on this network, so the single carrier leads vanilla; the nested W+W
// composition keeps its junk-active default).
func DefaultJunkActiveCfWarp() (Profile, string, error) {
        ladder, err := LadderFor(TargetCfWarp, "")
        if err != nil {
                return Profile{}, "", err
        }
        for _, tpl := range ladder {
                p, berr := tpl.Build()
                if berr != nil {
                        continue
                }
                if p.JunkCount > 0 {
                        return p, tpl.ID, nil
                }
        }
        return Profile{}, "", fmt.Errorf("transportwg: no junk-active profile in the cf-warp ladder")
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

// The measured junk-diversification envelope (Nova verified-seed set,
// 2026-08-10: 50 profiles field-proven on-device — distribution of Jc
// {4:10, 5:7, 6:7, 7:11, 8:15}, Jmin 30..70, Jmax = Jmin+20..Jmin+80
// capped at 150). Everything inside this envelope held a session with full
// probe coverage; the N25 heavy-junk experiment (Jc 110-125, Jmax~1000)
// bought nothing and cost ~60 KB per handshake, and ZERO junk never
// established a session at all (N2).
const (
        diversifyJunkCountLo  = 3
        diversifyJunkCountHi  = 8 // inclusive
        diversifyJunkMinLo    = 30
        diversifyJunkMinSpan  = 41 // 30..70 inclusive
        diversifyJunkMaxLo    = 20 // Jmax = Jmin + 20..80
        diversifyJunkMaxSpan  = 61
        diversifyJunkMaxCap   = 150
        diversifyJunkMaxEntry = 150 // templates with Jmax beyond this stay as measured
)

// DiversifyJunkFor deterministically jitters the junk triple of a BUILT-IN
// cf-warp profile for one candidate endpoint (Nova 1.31.x lineage: "у
// каждого из 50 свои параметры маскировки, поэтому набор не опознаётся как
// один"). Every endpoint of the walk draws its own (Jc, Jmin, Jmax) inside
// the measured envelope — a fleet of deployments (or one deployment's
// multi-endpoint probing) no longer shares a single fixed junk signature.
//
// Rules (red lines):
//   - the seed is the ENDPOINT STRING: the same endpoint always re-derives
//     the same triple (last-good reconnects stay byte-stable);
//   - profiles with JunkCount == 0 (vanilla / runtime-I1 quic) are untouched
//     — their shape IS the zero-junk decision;
//   - profiles whose JunkMax exceeds the envelope cap (the aggressive
//     Aether lineage) are untouched — measured values are not "improved"
//     by an unmeasured reshape;
//   - the I1 chain (the family character) never changes — only the junk
//     sizing around it.
func DiversifyJunkFor(candidate netip.AddrPort, prof *Profile) {
        if prof == nil || prof.JunkCount == 0 {
                return
        }
        if prof.JunkMax > diversifyJunkMaxEntry {
                return // measured aggressive shape — leave the field values alone
        }
        h := fnv.New64a()
        _, _ = h.Write([]byte(candidate.String()))
        rng := mrand.New(mrand.NewPCG(h.Sum64(), 0x626f78)) // "box"
        jc := diversifyJunkCountLo + rng.IntN(diversifyJunkCountHi-diversifyJunkCountLo+1)
        jmin := diversifyJunkMinLo + rng.IntN(diversifyJunkMinSpan)
        jmax := jmin + diversifyJunkMaxLo + rng.IntN(diversifyJunkMaxSpan)
        if jmax > diversifyJunkMaxCap {
                jmax = diversifyJunkMaxCap
        }
        if jmax < jmin {
                jmax = jmin // validator: jmin <= jmax
        }
        prof.JunkCount = uint32(jc)
        prof.JunkMin = uint32(jmin)
        prof.JunkMax = uint32(jmax)
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

// cfWarpLadderOrder is the default cf-warp ladder policy. FIELD 2026-09-18
// superseded the 2026-08-24 junk-first order: on this network the CF WARP
// outer UDP flow gets only a small per-flow budget (~3-4 KB), and the AWG
// junk/I1 packets sent before the handshake consume it. With junk the TLS
// flight is truncated (3684/4011) or the response never arrives; vanilla-off
// carries the full /cdn-cgi/trace end to end (loc=RU colo=DME/ARN, verified
// on 8.39.204.9:7103, 8.47.69.8:854, 8.39.214.9:500, 188.114.96.1:1701).
// Junk avoids passive WireGuard fingerprinting but breaks the data path here,
// so it is demoted behind vanilla-off; a seek ladder may still try it.
var cfWarpLadderOrder = []string{
        "vanilla-off", "quic-a", "quic-b", "sip-invite", "crlf-light", "crlf-aggressive",
}

// protonLadderOrder is the E-PROTON ladder (design 3.5): the QUIC-Initial
// family first (the live-verified reference shape), pure vanilla as the
// compatibility anchor, then the static payload families.
var protonLadderOrder = []string{
        "proton-quic", "proton-vanilla", "proton-sip", "proton-crlf",
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
        case TargetProton:
                if err := pushAll(protonLadderOrder); err != nil {
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
