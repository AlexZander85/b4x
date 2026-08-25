//go:build !linux

package fxvpn

import (
	"errors"
	"syscall"
)

// applyControlPlatform: routing constraints are a Linux/Keenetic feature.
// On other platforms a constrained policy fails closed (no silent unmarked
// socket); the zero-value policy remains usable for tests.
func applyControlPlatform(p DialPolicy, _ syscall.RawConn) error {
	if p.Constrained() || p.RequireMark {
		return errors.New("fxvpn: dial policy constraints unsupported on this platform")
	}
	return nil
}
