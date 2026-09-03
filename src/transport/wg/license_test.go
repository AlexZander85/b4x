package transportwg

import (
        "crypto/sha256"
        "encoding/hex"
        "testing"
)

// TestLicenseNoticeHash pins NOTICE.md content. If this test fails after an
// intentional NOTICE edit, update pinnedLicenseHash here AND the commit hash
// in the NOTICE header (and re-verify upstream LICENSE still matches).
func TestLicenseNoticeHash(t *testing.T) {
        // sha256 of the NOTICE.md as shipped with WG1 (dep pin v3.1.20260814,
        // commit 1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1) plus the PATCH-03
        // vendor fix record (timers.go data race; see NOTICE "Modifications")
        // and the E-PROTON P3 vendor seam (device.go/send.go InitPacketSpecFunc,
        // per-handshake I1 regeneration; see NOTICE "Modifications").
        const pinnedLicenseHash = "0a522127460aeb9e75deba501fa6d47da2adbc566fa428f743444f83d02c0265"
        sum := sha256.Sum256(noticeMD)
        got := hex.EncodeToString(sum[:])
        if got != pinnedLicenseHash {
                t.Fatalf("NOTICE.md changed: got %s, want %s — update pin + NOTICE header if intentional", got, pinnedLicenseHash)
        }
        if LicenseSHA256() != got {
                t.Fatalf("LicenseSHA256 mismatch")
        }
}
