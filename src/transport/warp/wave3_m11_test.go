package transportwarp

import (
	"crypto/x509"
	"testing"
	"time"
)

// TestM11NotBeforeClockSkew covers M-11: the self-signed client cert must be
// valid even when the router clock runs ~30 minutes ahead ("not yet valid" on
// the server). The check asserts NotBefore predates now by at least the hour
// of backdating margin.
func TestM11NotBeforeClockSkew(t *testing.T) {
	cert, err := ClientCertificate(newTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated cert: %v", err)
	}

	margin := time.Hour
	if !parsed.NotBefore.Before(time.Now().Add(-(margin - time.Minute))) {
		t.Fatalf("NotBefore=%v not backdated by >=1h (needed for +30min clock skew)", parsed.NotBefore)
	}
	// The cert must still be currently valid (NotBefore <= now <= NotAfter).
	if now := time.Now(); parsed.NotBefore.After(now) || parsed.NotAfter.Before(now) {
		t.Fatalf("generated cert not valid now: NotBefore=%v NotAfter=%v", parsed.NotBefore, parsed.NotAfter)
	}
}
