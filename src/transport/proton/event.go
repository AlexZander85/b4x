// Runtime primitives of the proton control plane (review L6: the former
// service_extras.go split by concern — this file holds the event shape and
// the identity-slot path resolution; the GUI projections live in views.go,
// the sanity probes in probes.go).
package proton

import (
	"strings"
	"time"
)

// Event is one taxonomy trace point (name snake_case, class kebab-case —
// the program canon). Detail carries only redacted-safe material.
type Event struct {
	Name   string    `json:"name"`
	Class  string    `json:"class,omitempty"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at,omitempty"`
}

// SiblingPath resolves name next to base (the identity-slot family: pins.json,
// serverlist.json, lastgood.json share the identity's directory).
func SiblingPath(base, name string) string {
	if i := strings.LastIndex(base, "/"); i > 0 {
		return base[:i+1] + name
	}
	return name
}
