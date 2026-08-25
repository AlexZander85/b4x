//go:build linux

package transportwarp

import "golang.org/x/sys/unix"

// socketProbeFD opens a scratch datagram socket for capability probing.
func socketProbeFD() (int, error) {
	return unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
}

// setMarkProbe attempts SO_MARK on the scratch fd.
func setMarkProbe(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 0x42)
}

func closeProbeFD(fd int) { _ = unix.Close(fd) }
