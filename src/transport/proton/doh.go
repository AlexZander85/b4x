// DoH-based alternative routing (design §2 step 2, port of Nova ProtonDoh.kt).
// From RF networks vpn-api.proton.me is transport-blocked (name resolves,
// ICMP answers, TCP 443 never opens) while Proton's OWN alternative-routing
// keeps working: a TXT record at d<Base32RFC4648(host)>.protonpro.xyz lists
// fallback hosts. The record is fetched through a chain of public DoH
// resolvers with the JSON API (Accept: application/dns-json):
//
//	https://dns.google/resolve -> https://cloudflare-dns.com/dns-query ->
//	https://dns11.quad9.net/dns-query
//
// TXT answers arrive as quoted, dot-terminated strings; the sorted result
// puts NAMES before IP ADDRESSES (a name carries its own TLS identity; an
// address dials with no SNI and relies on the pin alone).
package proton

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MirrorSuffix is Proton's alternative-routing zone.
const MirrorSuffix = ".protonpro.xyz"

// DefaultDoHResolvers is the fallback chain (design §2). The DoH channel
// itself is NOT pinned (public resolvers, normal chain validation) — only
// the resulting API candidates are pinned.
var DefaultDoHResolvers = []string{
	"https://dns.google/resolve",
	"https://cloudflare-dns.com/dns-query",
	"https://dns11.quad9.net/dns-query",
}

// DoHResolver resolves Proton mirror candidates through public DoH services.
type DoHResolver struct {
	// HTTP injects the client (tests: httptest stand). nil => a client with
	// Nova's timeout profile (connect 12s / overall 30s).
	HTTP      *http.Client
	Resolvers []string
	Now       func() time.Time
}

// MirrorName renders the alternative-routing TXT name for host:
// "d" + Base32 RFC 4648 (no padding) + ".protonpro.xyz" (DohClient.kt:59-61).
func MirrorName(host string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var sb strings.Builder
	buffer, bits := 0, 0
	for _, b := range []byte(host) {
		buffer = buffer<<8 | int(b)
		bits += 8
		for bits >= 5 {
			sb.WriteByte(alphabet[(buffer>>(bits-5))&0x1F])
			bits -= 5
		}
	}
	if bits > 0 {
		sb.WriteByte(alphabet[(buffer<<(5-bits))&0x1F])
	}
	return "d" + sb.String() + MirrorSuffix
}

// ResolveMirrors queries the TXT record through the resolver chain and
// returns the candidates, names before addresses. Empty result = "no
// alternative route" — the caller must report it, never silently continue
// with the direct host that already failed.
func (d *DoHResolver) ResolveMirrors(ctx context.Context, host string) ([]string, error) {
	if d == nil {
		return nil, fmt.Errorf("proton: doh resolver not configured")
	}
	name := MirrorName(host)
	resolvers := d.Resolvers
	if len(resolvers) == 0 {
		resolvers = DefaultDoHResolvers
	}
	client := d.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	var lastErr error
	for _, resolver := range resolvers {
		answers, err := d.queryTXT(ctx, client, resolver, name)
		if err != nil {
			lastErr = err
			continue
		}
		if len(answers) == 0 {
			continue
		}
		return sortCandidates(answers), nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("proton: doh %s: %w", name, lastErr)
	}
	return nil, fmt.Errorf("proton: doh %s: no answers on any resolver", name)
}

// queryTXT performs one GET {resolver}?name=...&type=TXT and returns the
// unquoted, dot-trimmed TXT strings.
func (d *DoHResolver) queryTXT(ctx context.Context, client *http.Client, resolver, name string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolver+"?name="+name+"&type=TXT", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseTXTAnswer(body)
}

// txtResponse is the minimal dns-json shape (Google/Cloudflare/Quad9 agree).
type txtResponse struct {
	Answer []struct {
		Name string `json:"name"`
		Data string `json:"data"`
		Type int    `json:"type"`
	} `json:"Answer"`
}

// parseTXTAnswer extracts TXT data values: trims quotes and the trailing
// dot the wire format carries.
func parseTXTAnswer(body []byte) ([]string, error) {
	var r txtResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("proton: doh answer: %w", err)
	}
	out := make([]string, 0, len(r.Answer))
	for _, a := range r.Answer {
		v := strings.TrimSpace(a.Data)
		v = strings.Trim(v, `"`)
		v = strings.TrimSuffix(v, ".")
		if v != "" {
			out = append(out, v)
		}
	}
	return out, nil
}

// sortCandidates orders names before IP-literal addresses (stable within the
// groups) — the ProtonDoh.kt rule: a name preserves its own TLS identity and
// is always preferred over a bare address.
func sortCandidates(list []string) []string {
	isIP := func(s string) bool {
		return strings.Count(s, ".") == 3 && strings.Trim(s, "0123456789.") == ""
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if !isIP(v) {
			out = append(out, v)
		}
	}
	for _, v := range list {
		if isIP(v) {
			out = append(out, v)
		}
	}
	return out
}
