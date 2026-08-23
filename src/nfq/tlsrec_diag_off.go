//go:build !tlsrcediag

package nfq

// tlsrecDiagEnabled gates the tlsrec-diagnostic layer (bd b4x-z1h).
// It is true only in builds made with -tags tlsrcediag (binary
// b4.exp-tlsrec). Default builds compile to false so the live holdch3
// behavior is byte-identical to previous binaries.
//
// Diagnostic scope (owner decision 2026-08-23): reframe ONE assembled
// youtube-video ClientHello record into TWO TLS records split right before
// the ECH extension (+5 bytes of record framing only, handshake bytes are
// untouched — RFC 8446 §5.1 allows fragmented handshakes). The verdict is
// read from pcap: if GGC answers with ServerHello, TSPU fails on
// multi-record ClientHellos; if not, it glues records and the cell is
// closed. No seq-NAT engine is built: post-handshake flow death is an
// accepted artifact of this diagnostic (the flow class is already doomed;
// see .ag/findings/tlsrec-step0-seq-consistency-2026-08-23.md).
const tlsrecDiagEnabled = false
