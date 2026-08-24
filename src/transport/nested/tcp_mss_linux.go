//go:build linux

package nested

import "syscall"

// setTCPMaxSeg applies TCP_MAXSEG before connect (explicit MSS, design 3.3).
func setTCPMaxSeg(fd uintptr, mss int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}
