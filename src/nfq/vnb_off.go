//go:build !vnb

package nfq

// vnbEnabled = false by default; true only in -tags vnb builds.
// See the layer file for scope. Default builds stay byte-identical.
const vnbEnabled = false
