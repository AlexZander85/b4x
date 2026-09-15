package transportwg

import (
        "net/netip"
        "testing"
)

// Nova 1.31.x junk diversification: every endpoint draws its own triple
// inside the measured envelope, deterministically; measured/zero-junk
// shapes are never touched.

func TestDiversifyJunkDeterministicPerEndpoint(t *testing.T) {
        cand := netip.MustParseAddrPort("162.159.193.5:2408")
        tpl, err := LookupProfile("quic-a")
        if err != nil {
                t.Fatal(err)
        }
        p1, err := tpl.Build()
        if err != nil {
                t.Fatal(err)
        }
        p2, err := tpl.Build()
        if err != nil {
                t.Fatal(err)
        }
        DiversifyJunkFor(cand, &p1)
        DiversifyJunkFor(cand, &p2)
        if p1.JunkCount != p2.JunkCount || p1.JunkMin != p2.JunkMin || p1.JunkMax != p2.JunkMax ||
                p1.InitPacket != p2.InitPacket {
                t.Fatalf("same endpoint must re-derive the same triple: %+v vs %+v", p1, p2)
        }
        if err := p1.Validate(); err != nil {
                t.Fatalf("diversified profile must pass validation: %v", err)
        }
}

func TestDiversifyJunkEnvelope(t *testing.T) {
        seen := map[[3]uint32]bool{}
        for i := 0; i < 500; i++ {
                cand := netip.MustParseAddrPort("162.159.193.5:2408") // address is fixed; vary via ports
                if i > 0 {
                        cand = netip.MustParseAddrPort("162.159.192." + itoa(1+i%250) + ":" + itoa(1000+i))
                }
                tpl, err := LookupProfile("quic-a")
                if err != nil {
                        t.Fatal(err)
                }
                p, err := tpl.Build()
                if err != nil {
                        t.Fatal(err)
                }
                DiversifyJunkFor(cand, &p)
                if p.JunkCount < 3 || p.JunkCount > 8 {
                        t.Fatalf("jc=%d outside the measured envelope", p.JunkCount)
                }
                if p.JunkMin < 30 || p.JunkMin > 70 {
                        t.Fatalf("jmin=%d outside the measured envelope", p.JunkMin)
                }
                lo, hi := p.JunkMin+20, p.JunkMin+80
                if hi > 150 {
                        hi = 150
                }
                if p.JunkMax < lo || p.JunkMax > hi {
                        t.Fatalf("jmax=%d outside [jmin+20..min(jmin+80,150)] for jmin=%d", p.JunkMax, p.JunkMin)
                }
                if err := p.Validate(); err != nil {
                        t.Fatalf("validation: %v", err)
                }
                seen[[3]uint32{p.JunkCount, p.JunkMin, p.JunkMax}] = true
        }
        if len(seen) < 100 {
                t.Fatalf("diversity too low: %d distinct triples over 500 endpoints", len(seen))
        }
}

func TestDiversifyJunkLeavesMeasuredShapesAlone(t *testing.T) {
        cand := netip.MustParseAddrPort("162.159.193.5:2408")

        // Zero-junk (vanilla / runtime-I1): the shape IS the decision.
        plain := Profile{}
        DiversifyJunkFor(cand, &plain)
        if plain.JunkCount != 0 || plain.JunkMin != 0 || plain.JunkMax != 0 {
                t.Fatalf("zero-junk profile was modified: %+v", plain)
        }

        // Aggressive Aether lineage (jmax 384 > envelope cap): measured values stay.
        agg, err := LookupProfile("crlf-aggressive")
        if err != nil {
                t.Fatal(err)
        }
        p, err := agg.Build()
        if err != nil {
                t.Fatal(err)
        }
        before := [3]uint32{p.JunkCount, p.JunkMin, p.JunkMax}
        DiversifyJunkFor(cand, &p)
        after := [3]uint32{p.JunkCount, p.JunkMin, p.JunkMax}
        if before != after {
                t.Fatalf("aggressive profile was reshaped: %v -> %v", before, after)
        }
}

func itoa(n int) string {
        if n == 0 {
                return "0"
        }
        var b [8]byte
        i := len(b)
        for n > 0 {
                i--
                b[i] = byte('0' + n%10)
                n /= 10
        }
        return string(b[i:])
}
