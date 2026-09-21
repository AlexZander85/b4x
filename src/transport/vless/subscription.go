package vless

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

// MaxSubscriptionBytes caps a subscription body (design §3.2 rail: a hostile
// or runaway upstream must not be able to exhaust the router's memory).
const MaxSubscriptionBytes = 16 << 20

// Fetch downloads one subscription body within ctx. Non-2xx and oversized
// bodies are errors; the caller decides whether to skip the source.
func Fetch(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	body, _, _, _, err := FetchConditional(ctx, client, rawURL, "", "")
	return body, err
}

// FetchConditional performs a conditional GET (design §8/§12): with a stored
// ETag/Last-Modified it sends If-None-Match/If-Modified-Since, and a 304
// answers (nil, etag, lastMod, true, nil) so the caller keeps its last-good
// nodes instead of re-downloading and re-parsing the whole list.
func FetchConditional(ctx context.Context, client *http.Client, rawURL, etag, lastMod string) (body []byte, newETag, newLastMod string, notModified bool, err error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", "", false, fmt.Errorf("vless: subscription request: %w", err)
	}
	req.Header.Set("User-Agent", "b4x-vless/1")
	req.Header.Set("Accept", "*/*")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "", false, fmt.Errorf("vless: subscription fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, lastMod, true, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", "", false, fmt.Errorf("vless: subscription http %d", resp.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, MaxSubscriptionBytes+1))
	if err != nil {
		return nil, "", "", false, fmt.Errorf("vless: subscription read: %w", err)
	}
	if len(body) > MaxSubscriptionBytes {
		return nil, "", "", false, fmt.Errorf("vless: subscription exceeds %d bytes", MaxSubscriptionBytes)
	}
	return body, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), false, nil
}

// DecodeBody normalizes a subscription body into one entry per line. It
// accepts plain text, base64 (std/url-safe, padded/raw) and JSON documents
// (returned as a single entry for the sing-box parser).
func DecodeBody(body []byte) []string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return []string{string(trimmed)}
	}
	if dec, ok := tryBase64(trimmed); ok {
		return splitLines(dec)
	}
	return splitLines(trimmed)
}

// ParseSubscription decodes and parses a subscription body with the same
// defensive accounting as ParseMany.
func ParseSubscription(body []byte) ([]Node, Stats) {
	return ParseMany(DecodeBody(body))
}

// tryBase64 decodes a compacted body if any standard variant applies AND the
// result looks like a node list (contains a scheme separator). The scheme
// check avoids mistaking arbitrary plain text for base64.
func tryBase64(in []byte) ([]byte, bool) {
	compact := stripWhitespace(in)
	if len(compact) == 0 {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		dec, err := enc.DecodeString(string(compact))
		if err == nil && len(dec) > 0 && bytes.Contains(dec, []byte("://")) {
			return dec, true
		}
	}
	return nil, false
}

func stripWhitespace(in []byte) []byte {
	out := make([]byte, 0, len(in))
	for _, b := range in {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		}
		out = append(out, b)
	}
	return out
}

func splitLines(in []byte) []string {
	raw := bytes.Split(in, []byte("\n"))
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		s := string(bytes.TrimSpace(l))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
