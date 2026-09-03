// BLK-7 (addendum §BLK-8): hot-path hand-off into the IP-learn sublayer.
// Called ONLY from the SNI ad-block decision points (TCP ClientHello / QUIC
// Initial, one decision per flow) and only on a BLOCK verdict, so the extra
// work never touches normal packet flow.
package nfq

import (
	"github.com/daniellavrushin/b4/adblock"
	"github.com/daniellavrushin/b4/sni"
)

// maybeLearnBlockedIP offers the dst-IP of a just-blocked flow to the kernel
// acceleration sublayer. CDN guard (mandatory, conservative): an IP that
// already matches an existing service set is shared infrastructure — other
// domains legitimately live there, so it must never enter the drop set.
// Everything else (private-range validation, dedup, capping, table
// application, aging) happens on the learn worker goroutine, never here.
func (w *Worker) maybeLearnBlockedIP(matcher *sni.SuffixSet, host string, pkt *pktInfo, listName string) {
	if !adblock.LearnEnabled() || matcher == nil || pkt == nil {
		return
	}
	if matched, _ := matcher.MatchIPWithSource(pkt.dst, pkt.srcMac); matched {
		adblock.CountLearnCDNSkip()
		return
	}
	adblock.EnqueueLearn(host, pkt.dst, pkt.srcMac, listName)
}
