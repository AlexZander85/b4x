// Service-facing extras of the proton control plane: the event shape for
// the supervisor rings, sibling-path resolution for the identity slot
// family, the exit/time sanity probes and the locations view.
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

// Event is one taxonomy trace point (name snake_case, class kebab-case —
// the program canon). Detail carries only redacted-safe material.
type Event struct {
	Name   string    `json:"name"`
	Class  string    `json:"class,omitempty"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at,omitempty"`
}

// SiblingPath resolves name next to base (the identity-slot family: pins.json,
// serverlist.json, lastgood.json share the identity's directory).
func SiblingPath(base, name string) string {
	if i := strings.LastIndex(base, "/"); i > 0 {
		return base[:i+1] + name
	}
	return name
}

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

// LocationsView normalizes the cached node list for the GUI dropdown
// (fxvpn parity): countries -> cities -> hosts with load and free marks.
type LocationsView struct {
	FetchedAt time.Time     `json:"fetched_at"`
	Source    string        `json:"source"`
	Countries []CountryView `json:"countries,omitempty"`
}

// CountryView groups the nodes of one country.
type CountryView struct {
	Code   string     `json:"code"`
	Cities []CityView `json:"cities"`
}

// CityView groups the nodes of one city.
type CityView struct {
	Name  string     `json:"name"`
	Hosts []HostView `json:"hosts"`
}

// HostView is one connectable node.
type HostView struct {
	Name       string `json:"name"`
	EntryIP    string `json:"entry_ip"`
	Load       int    `json:"load"`
	PeerPrefix string `json:"peer_prefix"`
}

// Locations renders the cached list (fresh-fetched or stale) as the view.
func (sc *ServerlistCache) Locations(ctx context.Context, sess *Session) (LocationsView, error) {
	nodes, _, err := sc.Get(ctx, sess)
	if err != nil {
		return LocationsView{}, err
	}
	view := LocationsView{Source: sc.Snapshot(), FetchedAt: sc.FetchedAt()}
	type cityBucket struct {
		name  string
		hosts []HostView
	}
	countries := map[string]*CountryView{}
	cities := map[string]*cityBucket{}
	var countryOrder []string
	for _, n := range nodes {
		c, ok := countries[n.Country]
		if !ok {
			c = &CountryView{Code: n.Country}
			countries[n.Country] = c
			countryOrder = append(countryOrder, n.Country)
		}
		key := n.Country + "\x00" + n.City
		bucket, ok := cities[key]
		if !ok {
			bucket = &cityBucket{name: n.City}
			cities[key] = bucket
			c.Cities = append(c.Cities, CityView{Name: bucket.name})
		}
		bucket.hosts = append(bucket.hosts, HostView{
			Name:       n.Name,
			EntryIP:    n.EntryIP,
			Load:       n.Load,
			PeerPrefix: PeerPrefix(n.PeerPubKey),
		})
	}
	// Assemble: countries in first-appearance order with their cities.
	for _, code := range countryOrder {
		view.Countries = append(view.Countries, *countries[code])
	}
	// Second pass: attach the accumulated hosts to the city entries.
	for i := range view.Countries {
		c := &view.Countries[i]
		for j := range c.Cities {
			key := c.Code + "\x00" + c.Cities[j].Name
			if bucket, ok := cities[key]; ok {
				c.Cities[j].Hosts = bucket.hosts
			}
		}
	}
	return view, nil
}

// PeerPrefix renders the diagnostic prefix of a peer key (first 6 chars —
// public material only).
func PeerPrefix(key string) string {
	if len(key) > 6 {
		return key[:6]
	}
	return key
}
