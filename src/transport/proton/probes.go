// Sanity probes of the proton control plane (review L6: the former
// service_extras.go split by concern): the NTP-wait clock check and the
// certificate notBefore parser.
package proton

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"time"
)

// TimeFresh is the coarse clock sanity check of the NTP-wait gate
// (patch-plan §6.3): TLS-dial the primary control host and verify the
// system time sits inside the served certificate validity window. A router
// without RTC whose clock drifted into 1970/2036 fails this check; a live
// network with a sane clock passes.
func TimeFresh(ctx context.Context, client *Client) bool {
	if client == nil {
		return false
	}
	direct := client.Endpoints.Direct
	if len(direct) == 0 {
		direct = DefaultDirectHosts
	}
	host := strings.TrimPrefix(strings.TrimPrefix(direct[0], "https://"), "http://")
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", host+":443")
	if err != nil {
		return false
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
	hsCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		return false
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false
	}
	now := time.Now()
	leaf := certs[0]
	return now.After(leaf.NotBefore.Add(-time.Minute)) && now.Before(leaf.NotAfter)
}

// parseCertNotBefore extracts notBefore from a PEM X.509 certificate body.
// Ok=false when the body is absent/unparseable (the guard then skips).
func parseCertNotBefore(pemBody string) (time.Time, bool) {
	blk, _ := pem.Decode([]byte(pemBody))
	if blk == nil {
		return time.Time{}, false
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return cert.NotBefore, true
}
