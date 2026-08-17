package ppe

import (
	"strings"
	"testing"
)

func TestSafeRunID(t *testing.T) {
	generation := strings.Repeat("ab", 32) // 64 hex chars
	auto := "auto-" + generation           // 69 chars: the real automatic run ID shape
	if !safeRunID(auto) {
		t.Fatalf("automatic run id %q (len=%d) must be accepted", auto, len(auto))
	}
	if !safeRunID("manual-42") {
		t.Fatal("short manual run id must be accepted")
	}
	if safeRunID("a") {
		t.Fatal("too-short run id must be rejected")
	}
	if safeRunID(auto + strings.Repeat("x", 60)) { // 129 chars
		t.Fatal("overlong run id must be rejected")
	}
	if safeRunID("auto-$(reboot)") {
		t.Fatal("run id with shell metacharacters must be rejected")
	}
	if safeRunID("auto-1;2") {
		t.Fatal("run id with separators must be rejected")
	}
}
