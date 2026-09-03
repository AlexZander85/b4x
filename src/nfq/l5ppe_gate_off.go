//go:build !l5ppe

package nfq

// l5PPEEnabled mirrors the main-package L5 gate (Часть 2.7): the L5 build
// disables the closed steer family so its RST/suppression cannot distort the
// handshake-window field test.
const l5PPEEnabled = false
