package managed

import (
	"strings"
	"testing"
)

func TestCatalogStampedEntryIsProductionReady(t *testing.T) {
	payload := []byte("version|catalog-stamped-v1\nresolver-a|dnscrypt|true|true|true|sdns://AQcAAAAAAAAAAA\n")
	cat, err := ParseCatalog(payload, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Entries) != 1 || !cat.Entries[0].ProductionReady() {
		t.Fatalf("stamped signed-catalog entry must be production-ready: %+v", cat.Entries)
	}
}

func TestLegacyCatalogEntryParsesButIsNotProductionReady(t *testing.T) {
	payload := []byte("version|catalog-legacy-v1\nresolver-a|dnscrypt|true|true|true\n")
	cat, err := ParseCatalog(payload, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Entries) != 1 || cat.Entries[0].ProductionReady() {
		t.Fatalf("legacy entry without signed stamp must not instantiate a managed provider: %+v", cat.Entries)
	}
}

func TestGenerateConfigWithStampIsSelfContained(t *testing.T) {
	s := specFixture("127.0.0.1:55331")
	s.ServerStamp = "sdns://AQcAAAAAAAAAAA"
	cfg, err := GenerateConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "server_names = ['b4x-upstream']") {
		t.Fatalf("static resolver alias missing:\n%s", cfg)
	}
	if !strings.Contains(cfg, "[static.'b4x-upstream']") || !strings.Contains(cfg, "stamp = 'sdns://AQcAAAAAAAAAAA'") {
		t.Fatalf("self-contained static stamp missing:\n%s", cfg)
	}
	if err := ValidateKeys(cfg); err != nil {
		t.Fatalf("self-contained generated config rejected: %v", err)
	}
}

func TestValidateKeysRejectsForeignStaticSection(t *testing.T) {
	cfg := "listen_addresses = ['127.0.0.1:5300']\n[static.'foreign']\nstamp = 'sdns://AQcAAAA'\n"
	if err := ValidateKeys(cfg); err == nil {
		t.Fatal("foreign static resolver section must be rejected")
	}
}
