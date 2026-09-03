//go:build !ipfragdiag

package nfq

// ipfragDiagEnabled gates the ipfrag2-diagnostic layer (Часть 2 промта
// NEXT_SESSION_TLSREC_IPFRAG2.md). True only in -tags ipfragdiag builds
// (binary b4.exp-ipfrag2). Default builds compile to false so live holdch3
// behavior stays identical.
//
// Hypothesis: if TSPU's IPv4 reassembler is weaker than its TCP pipeline,
// delivering the ClientHello segment as TWO IPv4 fragments (TCP header only
// in the offset-0 fragment) may slip the ECH-ext past the parser. Unlike
// tlsrec there is NO stream growth and NO seq problem: IP fragmentation is
// invisible to TCP numbering, so a PASS here is a real usable path, not a
// diagnostic. Verdict read from pcap: inbound data (ServerHello, first5=17..)
// from the GGC peer = reassembly gap found; silence = cell closed.
//
// Order: fragments go out DISORDERED (continuation fragment first) per the
// experiment name — weak in-order-only reassemblers fail open, strong ones
// reassemble regardless; Google's stack always reassembles fine.
const ipfragDiagEnabled = false

// ipfragDiagReverse sends the continuation fragment before the head
// fragment (disorder). Compiled into the tag-gated value below.
const ipfragDiagReverse = false
