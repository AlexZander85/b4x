package sock

import (
	"errors"
	"syscall"
	"testing"
)

func TestNewSenderWithMarkDevice_InvalidDeviceFails(t *testing.T) {
	_, err := NewSenderWithMarkDevice(0, "no-such-iface-b4x")
	if err == nil {
		t.Fatal("expected error when binding to a non-existent interface")
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("raw socket requires privileges: %v", err)
	}
}

func TestNewSenderWithMarkDevice_EmptyDeviceOK(t *testing.T) {
	s, err := NewSenderWithMarkDevice(0, "")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("raw socket requires privileges: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}
	defer s.Close()
}