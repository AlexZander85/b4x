//go:build ipfragdiag

package nfq

// ipfragDiagEnabled = true for the b4.exp-ipfrag2 build
// (go build -tags ipfragdiag). Scope and limits: see ipfrag2_diag_off.go.
const ipfragDiagEnabled = true

// Disorder order per the experiment name (ipfrag2-disorder).
const ipfragDiagReverse = true
