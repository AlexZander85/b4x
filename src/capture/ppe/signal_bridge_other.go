//go:build !unix

package ppe

import "context"

func StartNDMSignalBridge(context.Context, *Reconciler) func() { return func() {} }
