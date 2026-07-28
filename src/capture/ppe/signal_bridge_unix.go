//go:build unix

package ppe

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func StartNDMSignalBridge(ctx context.Context, reconciler *Reconciler) func() {
	if reconciler == nil {
		return func() {}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	bridgeCtx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-bridgeCtx.Done():
				return
			case <-ch:
				reconciler.Notify(ReconcileNDMEvent)
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		cancel()
		<-done
	}
}
