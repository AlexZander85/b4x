//go:build !quicsynrst

package nfq

// quicSynRstEnabled gates the L-quicsynrst layer (Часть 2.6 промта,
// ОДОБРЕНО владельцем 23.08). True only in -tags quicsynrnd/quicsynrst
// builds (binary b4.exp-quicsynrst, typically combined with -tags quicbound
// so the boundary sensors ride along for before/after comparison).
//
// Mechanic: after the FIRST classified doomed flow of a (device,dstIP) pair
// (youtube-video set + ECH detected at the inject funnel) the pair is armed
// for steerClientTTL (10 s, re-armed on every subsequent doomed flow). While
// armed, a bare outbound SYN of that pair receives an IMMEDIATE spoofed
// RST|ACK (<5 ms, "connection refused" semantics) instead of ~100 s of
// silence. Unlike closed v1 (RST after hold) the client has not sent any
// payload yet; unlike v2 nothing is silently dropped.
const quicSynRstEnabled = false
