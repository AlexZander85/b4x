package transportwarp

import (
	"context"
	"net/netip"
	"testing"
)

// b4x-4cl: the netstack carrier must resolve hostnames in-tunnel instead of
// refusing them, so a routing.mode=tunnel set that targets a DOMAIN works.

func TestNetstackCarrierResolveV4(t *testing.T) {
	answer := [4]byte{93, 184, 216, 34}
	c := &NetstackCarrier{}
	c.doh = NewDoHResolver().WithExchange(func(_ context.Context, query []byte) ([]byte, error) {
		return dohRespFor(query, answer, 60), nil
	})

	// A literal IPv4 passes straight through (no DoH).
	got, err := c.resolveV4(context.Background(), "1.2.3.4")
	if err != nil || got != netip.AddrFrom4([4]byte{1, 2, 3, 4}) {
		t.Fatalf("literal = %v, %v", got, err)
	}

	// A hostname resolves through the injected in-tunnel DoH exchange.
	got, err = c.resolveV4(context.Background(), "example.com")
	if err != nil || got != netip.AddrFrom4(answer) {
		t.Fatalf("hostname = %v, %v", got, err)
	}

	// v1 is IPv4-only: an IPv6 literal is refused.
	if _, err := c.resolveV4(context.Background(), "2606:4700::1"); err == nil {
		t.Fatal("expected IPv6 literal refusal")
	}
}
