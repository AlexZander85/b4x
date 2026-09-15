package torscan

import (
	"path/filepath"
	"testing"
	"time"
)

func TestProbeLedgerPersistsCooldownAndAggregateBudget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "probe-ledger.json")
	ledger := loadProbeLedger(path)

	for i := 0; i < probeBudgetPerWindow; i++ {
		addr := "192.0.2." + itoaBudget(i+1) + ":443"
		if !ledger.eligible(addr, now) {
			t.Fatalf("fresh address %s unexpectedly in cooldown", addr)
		}
		if !ledger.reserve(addr, now) {
			t.Fatalf("reservation %d unexpectedly rejected", i)
		}
	}
	if ledger.reserve("198.51.100.1:443", now) {
		t.Fatal("aggregate rate budget must reject attempts past the persisted window cap")
	}
	if err := ledger.save(path); err != nil {
		t.Fatal(err)
	}

	reloaded := loadProbeLedger(path)
	if reloaded.eligible("192.0.2.1:443", now.Add(time.Hour)) {
		t.Fatal("per-address cooldown must survive reload")
	}
	if reloaded.reserve("198.51.100.2:443", now.Add(time.Hour)) {
		t.Fatal("aggregate budget must survive reload")
	}

	later := now.Add(probeBudgetWindow + time.Second)
	if !reloaded.reserve("198.51.100.3:443", later) {
		t.Fatal("aggregate budget must reopen after the window expires")
	}
	if !reloaded.eligible("192.0.2.1:443", later) {
		t.Fatal("per-address cooldown must expire")
	}
}

func itoaBudget(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
