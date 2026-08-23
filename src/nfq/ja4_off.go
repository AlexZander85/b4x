//go:build !ja4

package nfq

// ja4Enabled = false by default; true only in -tags ja4 builds.
// See the layer file for scope. Default builds stay byte-identical.
const ja4Enabled = false
