//go:build !l5ppe

package main

// l5PPEEnabled gates the L5 field-test layer (Часть 2.7 промта): the PPE
// handshake-window rules (B4_PPE_PRE/FWD, connskip) are applied DIRECTLY at
// startup via the transaction backend — WITHOUT switching
// offload_policy to exclude and WITHOUT persisting anything into the live
// config. Rules live for the process lifetime; rollback = restart the
// holdch3 binary and flush the B4_PPE_* chains manually.
//
// Build: go build -tags l5ppe  → binary b4.exp-l5ppe.
const l5PPEEnabled = false
