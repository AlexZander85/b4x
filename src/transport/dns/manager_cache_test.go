package dnspath

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
)

func positiveCacheResponse(name string, txid uint16) []byte {
	resp := b4dns.BuildQuery(name, txid, 1)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[6:8], 1)
	rr := []byte{
		0xc0, 0x0c, // owner = question name
		0x00, 0x01, // A
		0x00, 0x01, // IN
		0x00, 0x00, 0x00, 0x1e, // TTL=30
		0x00, 0x04,
		1, 2, 3, 4,
	}
	return append(resp, rr...)
}

func TestManagerCachesValidatedResponseAndRewritesTransactionID(t *testing.T) {
	m, primary, _ := managerFixture(t)
	calls := 0
	primary.resolve = func(_ context.Context, q DNSQuery) (DNSResponse, error) {
		calls++
		return DNSResponse{
			Payload: positiveCacheResponse(q.Name, q.TxID),
			Fingerprint: ResponseFingerprint{
				QuestionName: q.Name,
				QuestionType: q.QType,
				TTLMin:       30,
				TTLMax:       30,
				AnswerDigest: "answer",
			},
		}, nil
	}
	if err := m.PreparePath(context.Background(), primary, false); err != nil {
		t.Fatal(err)
	}
	m.MarkPathHealth(primary.id, DNSPathHealth{State: CapReady})
	now := time.Now()
	profile := &DNSPathProfile{
		ProfileID: "dnsprof-cache", Status: ProfileStatusReady,
		NetworkContextID: "wan-1", ConfigGeneration: m.Generation(), RuntimeEpoch: "epoch-1",
		QuerySuiteVersion: "adns-suite-v1", Primary: primary.id,
		CandidateOutcomes: fullPromotionOutcomes(primary.id),
		CreatedAt:         now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := m.AdoptProfile(profile); err != nil {
		t.Fatal(err)
	}
	binding, err := m.NewBinding("cache-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m.promote(binding, nil)

	first, err := m.Resolve(context.Background(), DNSQuery{Name: "cache.example", QType: 1, TxID: 0x1111})
	if err != nil {
		t.Fatal(err)
	}
	if first.FromCache || calls != 1 {
		t.Fatalf("first resolve cache=%v calls=%d", first.FromCache, calls)
	}
	second, err := m.Resolve(context.Background(), DNSQuery{Name: "cache.example", QType: 1, TxID: 0x2222})
	if err != nil {
		t.Fatal(err)
	}
	if !second.FromCache || calls != 1 {
		t.Fatalf("second resolve cache=%v calls=%d", second.FromCache, calls)
	}
	if len(second.Payload) < 2 || binary.BigEndian.Uint16(second.Payload[:2]) != 0x2222 {
		t.Fatalf("cached response TXID=%x, want 2222", second.Payload[:2])
	}
	if c := m.Counters(); c.CacheHits != 1 || c.CacheMisses != 1 {
		t.Fatalf("cache counters = %+v", c)
	}
}
