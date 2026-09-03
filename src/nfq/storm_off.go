//go:build !storm

package nfq

// stormEnabled = false by default; true only in -tags storm builds. Scope: see the
// layer file. Default builds stay byte-identical.
const stormEnabled = false
