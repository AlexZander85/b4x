package nfq

// strategySink resolves where strategy-rewritten packets go — the coalesce
// datagram (udp.mode=coalesce) and the http_methodeol request rewrite.
// Production leaves strategyInjector nil and packets flow through the real
// raw-socket sender; tests substitute a fake (same discipline as
// clientInjector/actionSender). Returns nil when no sender exists
// (early-boot/lab workers) — callers fail open by accepting the packet
// untouched instead of dropping traffic they cannot reinject.
func (w *Worker) strategySink() packetInjector {
	if w == nil {
		return nil
	}
	if w.strategyInjector != nil {
		return w.strategyInjector
	}
	if w.sock != nil {
		return w.sock
	}
	return nil
}
