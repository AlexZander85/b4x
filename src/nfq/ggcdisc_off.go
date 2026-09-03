//go:build !ggcdisc

package nfq

// ggcDiscEnabled gates GGC-shard discovery (Часть 3 П.4 промта
// SESSION_PART3_PRODUCT.md). True only in -tags ggcdisc builds. Default
// builds compile to false so live behavior stays byte-identical.
//
// Scope: OBSERVATION FEEDER. Fetches redirector.googlevideo.com/report_mapping,
// resolves the current POP's googlevideo shard hostnames to their edge IPv4s
// and feeds them into the always-present scoped host-hint store for managed
// clients — so a seek hitting a FRESH CDN IP is classified (and its CH hold
// starts) before any QUIC/DNS observation of that exact address. Zero packet
// actions; never expands to prefixes; NEVER adds Google /16 ranges.
const ggcDiscEnabled = false
