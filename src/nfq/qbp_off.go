//go:build !qbp

package nfq

// qbpEnabled = false by default; true only in -tags qbp builds.
// See the layer file for scope. Default builds stay byte-identical.
const qbpEnabled = false
