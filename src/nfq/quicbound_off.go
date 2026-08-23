//go:build !quicbound

package nfq

// quicboundEnabled gates the L-quicbound DATA layer (Часть 2.5 промта
// NEXT_SESSION_TLSREC_IPFRAG2.md). True only in -tags quicbound builds
// (binary b4.exp-quicbound). Default builds compile to false so live
// holdch3 behavior stays identical.
//
// Scope: OBSERVATION ONLY. Counts doomed-TCP opens toward youtube-video
// IPs, correlates them with masked-QUIC activity of the same device/IP in
// a +-60 s window, classifies flow fate (FIN/RST/timeout), measures
// time-to-fallback (open -> next QUIC activity). Zero drops, zero RST,
// zero traffic actions. Verdict type: data collected / insufficient.
const quicboundEnabled = false
