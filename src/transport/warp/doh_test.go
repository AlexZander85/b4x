// E7 tests: DoH message layer (RFC 8484 wireformat + TTL-clamped cache).
package transportwarp

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// dohRespFor turns a query message into a NOERROR response carrying one A
// record with the given ttl.
func dohRespFor(query []byte, ip [4]byte, ttl uint32) []byte {
	resp := append([]byte(nil), query[:len(query)]...)
	resp[2] = 0x81 // QR=1, RD kept
	resp[3] = 0x80 // RA, rcode 0
	resp[6], resp[7] = 0x00, 0x01
	tail := []byte{
		0xC0, 0x0C, // pointer to qname
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
		0x00, 0x04,
	}
	tail = append(tail, ip[:]...)
	return append(resp, tail...)
}

func TestDoHResolverFailsClosedWithoutCarrier(t *testing.T) {
	r := NewDoHResolver()
	if _, _, err := r.ResolveA(context.Background(), "cloudflare.com"); !errors.Is(err, ErrDoHNotWired) {
		t.Fatalf("unwired resolver = %v", err)
	}
}

func TestDoHResolverParsesCachesAndClampsTTL(t *testing.T) {
	var clock struct {
		now atomic.Int64
	}
	nowFn := func() time.Time { return time.Unix(0, clock.now.Load()) }

	var calls atomic.Int32
	answer := [4]byte{104, 16, 132, 229}
	r := NewDoHResolver().WithClock(nowFn).WithExchange(func(ctx context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		return dohRespFor(query, answer, 1), nil // server TTL=1s → clamped up to 5s
	})
	clock.now.Store(time.Now().UnixNano())

	addrs, ttl, err := r.ResolveA(context.Background(), "one.one.one.one")
	if err != nil || len(addrs) != 1 || addrs[0] != netip.AddrFrom4(answer) {
		t.Fatalf("resolve = %v, %v", addrs, err)
	}
	if ttl < 4*time.Second || ttl > 5*time.Second {
		t.Fatalf("clamped ttl = %v (want ~5s from server TTL=1)", ttl)
	}

	// Cache hit: no second exchange while inside the clamped window.
	clock.now.Add(int64(3 * time.Second))
	if _, _, err := r.ResolveA(context.Background(), "one.one.one.one"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("cache miss: exchanges = %d", calls.Load())
	}

	// Expiry forces a refresh; huge upstream TTL is clamped down.
	clock.now.Add(int64(6 * time.Second))
	r2 := r.WithExchange(func(ctx context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		return dohRespFor(query, answer, 100000), nil
	})
	_, ttl2, err := r2.ResolveA(context.Background(), "one.one.one.one")
	if err != nil {
		t.Fatal(err)
	}
	if ttl2 > DoHMaxTTL {
		t.Fatalf("upper clamp failed: %v", ttl2)
	}
	if calls.Load() != 2 {
		t.Fatalf("exchanges = %d after expiry", calls.Load())
	}
}

func TestDoHResolverRejectsBadResponsesAndNeverCachesThem(t *testing.T) {
	var failMode atomic.Bool
	var calls atomic.Int32
	r := NewDoHResolver().WithExchange(func(ctx context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		if failMode.Load() {
			return []byte{0x12, 0x34, 0x81, 0x83}, nil // NXDOMAIN, truncated
		}
		return dohRespFor(query, [4]byte{1, 1, 1, 1}, 60), nil
	})

	failMode.Store(true)
	if _, _, err := r.ResolveA(context.Background(), "bad.test"); err == nil {
		t.Fatal("bad response accepted")
	}
	failMode.Store(false)
	if _, _, err := r.ResolveA(context.Background(), "good.test"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("negative result was cached? calls=%d", calls.Load())
	}
}
