//go:build !echflow

package nfq

// echFlowEnabled gates the tcp_has_ech flow classifier (Часть 3 П.2 промта
// SESSION_PART3_PRODUCT.md). True only in -tags echflow builds (binary
// b4.exp-echflow). Default builds compile to false so live behavior stays
// byte-identical.
//
// Scope: OBSERVATION ONLY. Marks a TCP flow the first time its ClientHello
// record shows an ECH extension (TSPU cuts Google TCP by ECH-ext presence,
// YOUTUBE_DATAPLANE.md §2) and emits a one-time [ech-flow] log marker plus a
// throttled summary. Zero drops, zero RST, zero traffic actions — the claim
// is data for future ABD branching ("doomed by policy" vs "alive").
const echFlowEnabled = false
