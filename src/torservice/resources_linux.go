//go:build linux

package torservice

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const lowMemoryThresholdBytes = 128 << 20

func platformResourceSnapshot(pid int) platformResources {
	p := platformResources{}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		p.fdLimit = lim.Cur
	}
	if entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
		p.fdUsed = len(entries)
	}
	if f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
						p.rssBytes = kb * 1024
					}
				}
				break
			}
		}
		_ = f.Close()
	}
	p.lowMemory = machineMemoryBytes() > 0 && machineMemoryBytes() <= lowMemoryThresholdBytes
	return p
}

func machineMemoryBytes() uint64 {
	f, err := os.Open(filepath.Clean("/proc/meminfo"))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}
