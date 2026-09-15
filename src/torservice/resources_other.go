//go:build !linux

package torservice

func platformResourceSnapshot(pid int) platformResources {
	_ = pid
	return platformResources{}
}
