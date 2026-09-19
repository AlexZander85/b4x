package awgwarpservice

// Tests for the hostname-dial seam (b4x-1ev). The success path needs a live
// gVisor netstack (a real Session), which unit tests never build — the pure
// resolver helper and the two honest refusal paths are covered instead, the
// same shape as the existing carrier refusal test.

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestFirstIPv4PicksFirstV4(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    string
		wantErr bool
	}{
		{name: "skips v6", in: []string{"2606:4700::1", "1.2.3.4"}, want: "1.2.3.4"},
		{name: "unmaps 4in6", in: []string{"::ffff:5.6.7.8"}, want: "5.6.7.8"},
		{name: "first v4 wins", in: []string{"1.2.3.4", "5.6.7.8"}, want: "1.2.3.4"},
		{name: "skips garbage", in: []string{"nope", "9.9.9.9"}, want: "9.9.9.9"},
		{name: "v6 only", in: []string{"2606:4700::1"}, wantErr: true},
		{name: "all garbage", in: []string{"nope", "also-nope"}, wantErr: true},
		{name: "empty", in: nil, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := firstIPv4(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("firstIPv4(%v) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("firstIPv4(%v): %v", tc.in, err)
			}
			if want := netip.MustParseAddr(tc.want); got != want {
				t.Fatalf("firstIPv4(%v) = %v, want %v", tc.in, got, want)
			}
		})
	}
}

func TestDialStreamHostRefusesWithoutSession(t *testing.T) {
	rt, err := Build(testConfig(filepath.Join(t.TempDir(), "slot.json")), Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := rt.DialStreamHost(context.Background(), "rr1---sn-4g5edndd.googlevideo.com", 443); !errors.Is(err, ErrNotListening) {
		t.Fatalf("err = %v, want ErrNotListening", err)
	}
	rt.mu.Lock()
	fails := rt.dialFail
	rt.mu.Unlock()
	if fails != 1 {
		t.Fatalf("dialFail = %d, want 1", fails)
	}
}

func TestDialStreamHostRefusesKernelMode(t *testing.T) {
	rt, err := Build(testConfig(filepath.Join(t.TempDir(), "slot.json")), Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rt.mu.Lock()
	rt.kernelMode = true
	rt.mu.Unlock()
	if _, err := rt.DialStreamHost(context.Background(), "example.com", 443); !errors.Is(err, ErrKernelMode) {
		t.Fatalf("err = %v, want ErrKernelMode", err)
	}
}
