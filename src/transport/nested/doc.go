// Package nested composes CROSS-TRANSPORT nested tunnels from the two
// shipping engines (E-NM design: .ag/research/warp-nested-matrix-design.md):
//
//	transportwg   — AWG/WG layers (gool core, WG6 nested composition)
//	transportwarp — MASQUE CONNECT-IP H2 layers (E5 parent-link contracts)
//
// Combinations covered by ONE carrier abstraction on the OUTER side
// instead of per-pair designs:
//
//	M+W  masque-h2 outer, awg inner   (escalation path of the non-RU tree)
//	W+W  awg outer, awg inner         (gool classic; delegates to WG6)
//	W+M  awg outer, masque-h2 inner   (H2 speed inside a punched UDP hole)
//
// The outer's DATA-PLANE mode decides the carrier, never the transports:
//
//   - kernel-TUN outer  -> KernelRouteCarrier (/32 pin through the outer
//     device, owned snapshot/restore, re-asserted every supervisor tick —
//     the documented zapret-gui gap "restart loses the pin" is closed here);
//   - userspace netstack outer -> NetstackCarrier (gVisor stack of the
//     outer session acts as the virtual NIC);
//   - MASQUE CONNECT-IP outer -> MasqueDatagramCarrier (UDP datagrams ride
//     as crafted IPv4 packets inside the capsule stream).
//
// Red lines (design §8) enforced structurally: no route without BOTH trust
// gates, no silent fallback between carriers, one CF device per layer,
// vanilla-safe profiles against the CF edge, foreign routes never deleted.
//
// CARRIER GATING POSTURES (PATCH-25: the three carriers are deliberately
// asymmetric — the gate lives where the ownership lives; never "soften" one
// to match another):
//
//	KernelRouteCarrier  HARD proofOK gate on both dials (the route pin is
//	                    owned host state — dialing through an unproven pin
//	                    sends traffic to a dead/foreign device);
//	                    assert-loop repairs pins across outer generations.
//	MasqueDatagramCarrier  SOFT wake-up posture: writes fail closed on an
//	                    unproven plane, but a plane that lost its route
//	                    releases the gate at the supervisor (fail-open
//	                    semantics owned by the plane, buffered wake-up).
//	NetstackCarrier     the LIVE gVisor stack IS the proof — no separate
//	                    gate bookkeeping (a dead session kills the stack).
//
// TEARDOWN OWNERSHIP (PATCH-25, updated after PATCH-06/07): the kernel
// carrier is ONE per W+M runtime lifetime; Restore deletes every owned pin
// ALWAYS and re-issues only exact-prefix foreign prevs (covering prevs like
// `default` are never displaced by a /32 pin and are never re-issued).
// Pair teardown order stays child-first: inner supervisor -> carrier
// Restore -> carrier Close.
package nested
