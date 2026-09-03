//go:build !linux

package nested

// setTCPMaxSeg is a documented no-op off-linux: TCP_MAXSEG clamping of
// carrier-dialed sockets is a kernel-route (linux) capability.
func setTCPMaxSeg(fd uintptr, mss int) error { return nil }
