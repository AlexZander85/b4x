package nfq

import (
	"net"
	"sync"

	"github.com/florianl/go-nfqueue"
)

var (
	ifaceCache sync.Map
)

func getIfaceName(idx uint32) string {
	if idx == 0 {
		return ""
	}

	if v, ok := ifaceCache.Load(idx); ok {
		return v.(string)
	}

	iface, err := net.InterfaceByIndex(int(idx))
	if err != nil {
		return ""
	}

	actual, _ := ifaceCache.LoadOrStore(idx, iface.Name)
	return actual.(string)
}

func (w *Worker) matchesInterface(a nfqueue.Attribute) bool {
	cfg := w.getConfig()
	ifaces := cfg.Queue.Interfaces
	matched := len(ifaces) == 0

	var idx uint32
	if a.OutDev != nil && *a.OutDev != 0 {
		idx = *a.OutDev
	} else if a.InDev != nil {
		idx = *a.InDev
	}

	if !matched && idx == 0 {
		matched = true // can't determine, preserve existing fail-open behavior
	}
	if !matched {
		name := getIfaceName(idx)
		for _, allowed := range ifaces {
			if name == allowed {
				matched = true
				break
			}
		}
	}
	if matched && a.Payload != nil {
		w.observePPEPassiveRaw(cfg, *a.Payload)
	}
	return matched
}
