//go:build !linux

package transportwarp

// Non-Linux builds cannot set SO_MARK at all: probes report unavailable so
// constrained-socket tests assert the fail-closed branch.
func socketProbeFD() (int, error) { return -1, errNotUDPPacketConn }

func setMarkProbe(int) error { return errNotUDPPacketConn }

func closeProbeFD(int) {}
