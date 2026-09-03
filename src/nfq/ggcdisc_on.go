//go:build ggcdisc

package nfq

// ggcDiscEnabled = true for the b4.exp-ggcdisc build
// (go build -tags "l5ppe echflow ggcdisc"). Scope: see ggcdisc_off.go.
const ggcDiscEnabled = true
