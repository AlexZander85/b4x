package torsnowflake

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	sflib "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"

	"github.com/daniellavrushin/b4/transport/tor"

	"go.uber.org/goleak"
)

// The snowflake client library's turbo-tunnel drags kcp-go package-init
// scheduler goroutines into every importing process (process-lifetime by
// design, not a leak) — captured once here.
var initIgnore = goleak.IgnoreCurrent()

func verifyNoLeaks(t *testing.T) {
	t.Helper()
	goleak.VerifyNone(t, initIgnore)
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, initIgnore)
}

const fp1 = "0123456789ABCDEF0123456789ABCDEF01234567"

func noDial() tor.EgressDialFunc {
	return func(ctx context.Context, class tor.ConnClass, host string, port uint16) (net.Conn, error) {
		return nil, errors.New("no dial in this test")
	}
}

func TestSnowflakeConfigFromArgs(t *testing.T) {
	cfg, key, err := snowflakeConfigFromArgs(map[string]string{
		"url":           "https://broker.example/",
		"fronts":        "a.example,b.example",
		"ice":           "stun:stun.example:3478, stun:stun2.example:443",
		"max":           "3",
		"utls-imitate":  "hellorandomizedalpn",
		"utls-nosni":    "1",
		"fingerprint":   fp1,
		"ampcache":      "https://amp.example/",
		"someother-arg": "ignored-by-config",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.BrokerURL != "https://broker.example/" || cfg.AmpCacheURL != "https://amp.example/" {
		t.Fatalf("rendezvous = %q / %q", cfg.BrokerURL, cfg.AmpCacheURL)
	}
	if len(cfg.FrontDomains) != 2 || cfg.FrontDomains[0] != "a.example" {
		t.Fatalf("fronts = %v", cfg.FrontDomains)
	}
	if len(cfg.ICEAddresses) != 2 || cfg.ICEAddresses[1] != "stun:stun2.example:443" {
		t.Fatalf("ice = %v (space trimming expected)", cfg.ICEAddresses)
	}
	if cfg.Max != 3 {
		t.Fatalf("max = %d", cfg.Max)
	}
	if cfg.UTLSClientID != "hellorandomizedalpn" || !cfg.UTLSRemoveSNI {
		t.Fatalf("utls = %q/%t", cfg.UTLSClientID, cfg.UTLSRemoveSNI)
	}
	if cfg.BridgeFingerprint != fp1 {
		t.Fatalf("fingerprint = %q", cfg.BridgeFingerprint)
	}
	if !strings.Contains(key, "url=https://broker.example/") || !strings.Contains(key, "someother-arg=ignored-by-config") {
		t.Fatalf("cache key = %q", key)
	}

	// front= appends to fronts
	if _, _, err := snowflakeConfigFromArgs(map[string]string{"url": "https://b/", "front": "f.example"}); err != nil {
		t.Fatalf("front= form: %v", err)
	}

	// refusals
	for _, bad := range []map[string]string{
		{"sqsqueue": "https://sqs/", "url": "https://b/"}, // sqs-rejected (double gate)
		{}, // no rendezvous
		{"url": "https://b/", "max": "9"},
		{"url": "https://b/", "max": "zero"},
	} {
		if _, _, err := snowflakeConfigFromArgs(bad); err == nil {
			t.Fatalf("args %v must fail", bad)
		}
	}

	// default max when absent
	cfgDef, _, err := snowflakeConfigFromArgs(map[string]string{"url": "https://b/"})
	if err != nil || cfgDef.Max != snowflakeDefaultMax {
		t.Fatalf("default max: %+v err=%v", cfgDef, err)
	}
}

func TestSnowflakeCacheKeyStability(t *testing.T) {
	// same args in different map iteration orders serialize identically
	a := map[string]string{"url": "https://b/", "max": "2", "fronts": "x.example"}
	b := map[string]string{"fronts": "x.example", "max": "2", "url": "https://b/"}
	if serializeArgs(a) != serializeArgs(b) {
		t.Fatalf("keys diverge: %q vs %q", serializeArgs(a), serializeArgs(b))
	}
}

func TestSnowflakeAdapterHooksInstalled(t *testing.T) {
	defer verifyNoLeaks(t)
	adapter := NewSnowflakeAdapter(noDial(), nil)
	if sflib.NetWrapper == nil {
		t.Fatal("NetWrapper hook not installed")
	}
	if sflib.BrokerDialContext == nil {
		t.Fatal("BrokerDialContext hook not installed")
	}
	// the nil-inner guard: pion on nil silently builds its own net — the
	// wrapper must refuse (G154)
	var nilNet interface {
		Dial(string, string) (net.Conn, error)
	}
	_ = nilNet
	wrapped := adapter.prot.wrap(nil)
	if _, err := wrapped.Dial("tcp", "1.2.3.4:443"); err == nil {
		t.Fatal("nil inner net must fail loud (G154)")
	}
}

func TestSnowflakeAdapterParseArgsAndCache(t *testing.T) {
	defer verifyNoLeaks(t)
	adapter := NewSnowflakeAdapter(noDial(), nil)

	args := map[string]string{"url": "https://broker.example/", "max": "2"}
	if _, err := adapter.ParseArgs(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := adapter.ParseArgs(args); err != nil {
		t.Fatalf("parse 2: %v", err)
	}
	if adapter.ClientCacheLen() != 0 {
		t.Fatal("clients are created lazily at Dial, cache must be empty")
	}
	// sqs double-gate
	if _, err := adapter.ParseArgs(map[string]string{"url": "https://b/", "sqsqueue": "https://s/"}); err == nil {
		t.Fatal("sqsqueue through the adapter must fail (double gate)")
	}
}

func TestSnowflakeAdapterBoundedCache(t *testing.T) {
	defer verifyNoLeaks(t)
	adapter := NewSnowflakeAdapter(noDial(), nil)
	for i := 0; i < snowflakeMaxClients+5; i++ {
		key := fmt.Sprintf("k%d", i)
		if _, err := adapter.client(key, func() (*sflib.Transport, error) {
			return &sflib.Transport{}, nil
		}); err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
	}
	if got := adapter.ClientCacheLen(); got != snowflakeMaxClients {
		t.Fatalf("cache = %d, want bounded %d", got, snowflakeMaxClients)
	}
	// the oldest keys were evicted, the newest survive
	if _, err := adapter.client("k0", func() (*sflib.Transport, error) {
		return &sflib.Transport{}, nil
	}); err != nil {
		t.Fatal("evicted key must rebuild")
	}
}
