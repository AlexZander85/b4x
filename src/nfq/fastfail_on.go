//go:build fastfail

package nfq

// fastFailEnabled = true for -tags fastfail builds (bd b4x-693).
// Scope and guards: see fastfail.go. Default builds stay byte-identical.
const fastFailEnabled = true
