//go:build !fastfail

package nfq

// fastFailEnabled = false by default; true only in -tags fastfail builds.
// Every fast-fail hook starts with an early return on this const, so default
// builds behave exactly like the anchor (the store stays unallocated); some
// dead code may remain in the binary — behaviorally inert.
const fastFailEnabled = false
