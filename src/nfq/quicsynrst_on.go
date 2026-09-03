//go:build quicsynrst

package nfq

// quicSynRstEnabled = true for the b4.exp-quicsynrst build
// (go build -tags "quicbound,quicsynrst"). Scope: see quicsynrst_off.go.
const quicSynRstEnabled = true
