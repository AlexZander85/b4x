// Minimal Digest Access Authentication profile (RFC 7616) for the SurfEasy
// API channel — written in-house per design §7 red line 0 (~100 lines core,
// no external dependency). The reference specification is Alexey71/
// go-http-digest-auth-client v1.1.3 (the library every opera-proxy fork
// rides): its WWW-Authenticate parser shape, KD hash chain and Authorization
// header field order are reproduced byte-for-byte and locked by golden-vector
// tests (digest_test.go).
//
// Supported profile (design §7.0):
//   - algorithm: MD5 only ("", "MD5" accepted; anything else => Failure
//     ClassAPIAlgorithm);
//   - qop: token "auth" must be offered; auth-int is NOT supported;
//   - nc counter is monotonic per nonce (%08x), reset on each new nonce;
//   - cnonce comes from crypto/rand;
//   - stale=true re-challenge is retried transparently with the same
//     credentials; a stale=false 401 after a presented response propagates
//     to the caller for refuse classification.
package opera

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

const (
	digestMaxAttempts   = 3   // plain -> challenged -> (stale re-challenge)
	digestDrainLimit    int64 = 128 * 1024
	digestBodyBufLimit  int64 = 1 << 20
)

// ---------------------------------------------------------------------------
// WWW-Authenticate parsing (gorilla-parser lineage, same shape as the
// reference implementation: quoted-string aware list/pair splitting).
// ---------------------------------------------------------------------------

// parseAuthList splits a comma-separated header value honoring quoting.
func parseAuthList(value string) []string {
	var (
		list   []string
		escape bool
		quote  bool
		buf    bytes.Buffer
	)
	for _, r := range value {
		switch {
		case escape:
			buf.WriteRune(r)
			escape = false
		case quote:
			if r == '\\' {
				escape = true
			} else {
				if r == '"' {
					quote = false
				}
				buf.WriteRune(r)
			}
		case r == ',':
			list = append(list, strings.TrimSpace(buf.String()))
			buf.Reset()
		case r == '"':
			quote = true
			buf.WriteRune(r)
		default:
			buf.WriteRune(r)
		}
	}
	if s := buf.String(); s != "" {
		list = append(list, strings.TrimSpace(s))
	}
	return list
}

// parseAuthPairs extracts key=value pairs with unquoting; elements without
// '=' become keys with an empty value. Keys are normalized to lowercase
// (attribute names are case-insensitive per RFC 9110 §11.6.1); values stay
// byte-exact.
func parseAuthPairs(value string) map[string]string {
	m := make(map[string]string)
	for _, pair := range parseAuthList(strings.TrimSpace(value)) {
		i := strings.Index(pair, "=")
		switch {
		case i < 0:
			m[strings.ToLower(pair)] = ""
		case i == len(pair)-1:
			m[strings.ToLower(pair[:i])] = ""
		default:
			v := pair[i+1:]
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			m[strings.ToLower(pair[:i])] = v
		}
	}
	return m
}

// digestChallenge is a parsed WWW-Authenticate Digest challenge.
type digestChallenge struct {
	realm     string
	nonce     string
	opaque    string
	qop       string // raw offer (comma list); resolved by resolveQop
	algorithm string // raw; normalized by normalizeAlgorithm
	stale     bool
}

func parseDigestChallenge(header string) (*digestChallenge, error) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Digest") {
		return nil, fmt.Errorf("not a Digest challenge")
	}
	vals := parseAuthPairs(parts[1])
	ch := &digestChallenge{
		realm:     vals["realm"],
		nonce:     vals["nonce"],
		opaque:    vals["opaque"],
		qop:       vals["qop"],
		algorithm: vals["algorithm"],
		stale:     strings.EqualFold(vals["stale"], "true"),
	}
	if ch.nonce == "" {
		return nil, fmt.Errorf("digest challenge without nonce")
	}
	return ch, nil
}

// normalizeAlgorithm gates the supported profile: MD5 only (empty means
// MD5 per RFC 7616 §3.3 default). Anything else is a structured failure.
func normalizeAlgorithm(raw string) (string, error) {
	switch strings.ToUpper(raw) {
	case "", "MD5":
		return "MD5", nil
	default:
		return "", newFailure(ClassAPIAlgorithm,
			fmt.Sprintf("unsupported digest algorithm %q (profile: MD5 only)", raw), nil)
	}
}

// resolveQop picks the "auth" token from a qop offer. auth-int is not in
// profile; a challenge without usable qop is rejected outright (the real
// SurfEasy API always offers auth).
func resolveQop(offer string) (string, error) {
	for _, tok := range strings.Split(offer, ",") {
		if strings.TrimSpace(tok) == "auth" {
			return "auth", nil
		}
	}
	return "", fmt.Errorf("no supported qop in offer %q (profile: auth only, no auth-int)", offer)
}

// ---------------------------------------------------------------------------
// Hash chain (identical formulas to the reference client).
// ---------------------------------------------------------------------------

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func digestHA1(username, realm, password string) string {
	return md5hex(username + ":" + realm + ":" + password)
}

func digestHA2(method, uri string) string {
	return md5hex(method + ":" + uri)
}

func digestResponse(ha1, nonce, nc, cnonce, qop, ha2 string) string {
	return md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

// renderAuthorization emits the header in the reference field order
// (username, realm, nonce, uri, response, algorithm, cnonce, opaque, qop,
// nc): quoted values stay quoted, tokens unquoted — locked by golden test.
func renderAuthorization(p map[string]string) string {
	var buf bytes.Buffer
	buf.WriteString("Digest ")
	writeQuoted := func(key, val string) {
		if val != "" {
			fmt.Fprintf(&buf, "%s=\"%s\", ", key, val)
		}
	}
	writeToken := func(key, val string) {
		if val != "" {
			fmt.Fprintf(&buf, "%s=%s, ", key, val)
		}
	}
	writeQuoted("username", p["username"])
	writeQuoted("realm", p["realm"])
	writeQuoted("nonce", p["nonce"])
	writeQuoted("uri", p["uri"])
	writeQuoted("response", p["response"])
	writeToken("algorithm", p["algorithm"])
	writeQuoted("cnonce", p["cnonce"])
	writeQuoted("opaque", p["opaque"])
	writeToken("qop", p["qop"])
	writeToken("nc", p["nc"])
	return strings.TrimSuffix(buf.String(), ", ")
}

// ---------------------------------------------------------------------------
// Session: one nonce's worth of Digest state.
// ---------------------------------------------------------------------------

// cnonceFunc produces client nonce material. Default: crypto/rand.
type cnonceFunc func() (string, error)

func randomCnonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type digestSession struct {
	mu        sync.Mutex
	username  string
	password  string
	realm     string
	nonce     string
	opaque    string
	qop       string
	algorithm string
	nc        uint32
	cnonceGen cnonceFunc
}

func newDigestSession(username, password string) *digestSession {
	return &digestSession{username: username, password: password, cnonceGen: randomCnonce}
}

// ready reports whether a challenge has been adopted.
func (s *digestSession) ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonce != ""
}

// reset adopts a fresh challenge (nc restarts at zero; first use is 1).
func (s *digestSession) reset(ch *digestChallenge) error {
	alg, err := normalizeAlgorithm(ch.algorithm)
	if err != nil {
		return err
	}
	qop, err := resolveQop(ch.qop)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.realm, s.nonce, s.opaque = ch.realm, ch.nonce, ch.opaque
	s.qop, s.algorithm = qop, alg
	s.nc = 0
	return nil
}

// authorize increments nc monotonically and renders the Authorization
// header value for this request.
func (s *digestSession) authorize(method, uri string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cnonce, err := s.cnonceGen()
	if err != nil {
		return "", fmt.Errorf("cnonce: %w", err)
	}
	s.nc++
	params := map[string]string{
		"username":  s.username,
		"realm":     s.realm,
		"nonce":     s.nonce,
		"uri":       uri,
		"response":  "",
		"algorithm": s.algorithm,
		"cnonce":    cnonce,
		"opaque":    s.opaque,
		"qop":       s.qop,
		"nc":        fmt.Sprintf("%08x", s.nc),
	}
	ha1 := digestHA1(s.username, s.realm, s.password)
	ha2 := digestHA2(method, uri)
	params["response"] = digestResponse(ha1, s.nonce, params["nc"], cnonce, s.qop, ha2)
	return renderAuthorization(params), nil
}

// ---------------------------------------------------------------------------
// Transport: challenge/retry wrapper over a base RoundTripper.
// ---------------------------------------------------------------------------

// digestTransport implements http.RoundTripper: it fires requests without
// credentials, parses a 401 Digest challenge, retries once with a fresh
// response, and honors stale=true re-challenges transparently. A final
// 401 (stale=false after a presented response) is passed through untouched
// so seclient maps it to ClassAPIAuthRefused at one place.
type digestTransport struct {
	base     http.RoundTripper
	session  *digestSession
	drainLim int64
}

func newDigestTransport(username, password string, base http.RoundTripper) *digestTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &digestTransport{
		base:     base,
		session:  newDigestSession(username, password),
		drainLim: digestDrainLimit,
	}
}

func (d *digestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	presented := false
	for attempt := 0; attempt < digestMaxAttempts; attempt++ {
		reqCopy, err := replayable(req)
		if err != nil {
			return nil, err
		}
		if d.session.ready() {
			hdr, err := d.session.authorize(req.Method, req.URL.RequestURI())
			if err != nil {
				return nil, err
			}
			reqCopy.Header.Set("Authorization", hdr)
			presented = true
		} else {
			reqCopy.Header.Del("Authorization")
		}

		resp, err := d.base.RoundTrip(reqCopy)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusUnauthorized {
			return resp, nil
		}
		header := resp.Header.Get("WWW-Authenticate")
		if header == "" {
			return resp, nil // non-Digest 401: caller classifies
		}
		ch, err := parseDigestChallenge(header)
		if err != nil {
			d.drain(resp)
			return nil, err
		}
		// Presented a response and rejected without staleness => refusal.
		// (First-challenge and stale=true paths fall through to a retry.)
		if presented && !ch.stale {
			return resp, nil
		}
		if err := d.session.reset(ch); err != nil {
			d.drain(resp)
			return nil, err
		}
		d.drain(resp)
	}
	return nil, fmt.Errorf("digest auth did not converge within %d attempts", digestMaxAttempts)
}

// drain discards a bounded response body so keep-alive connections survive.
func (d *digestTransport) drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, d.drainLim))
	_ = resp.Body.Close()
}

// CloseIdleConnections forwards to the base transport so http.Client's
// idle-pool teardown reaches through this wrapper (TOFU tests and OP3
// supervisor rely on forced re-handshakes).
func (d *digestTransport) CloseIdleConnections() {
	if ci, ok := d.base.(interface{ CloseIdleConnections() }); ok {
		ci.CloseIdleConnections()
	}
}

// replayable clones req guaranteeing Body can be re-sent: GetBody wins,
// otherwise the original body is buffered (our form bodies are tiny).
func replayable(req *http.Request) (*http.Request, error) {
	if req.Body == nil {
		return req.Clone(req.Context()), nil
	}
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		rc := req.Clone(req.Context())
		rc.Body = body
		return rc, nil
	}
	buf := new(bytes.Buffer)
	n, err := io.Copy(buf, io.LimitReader(req.Body, digestBodyBufLimit))
	if err != nil {
		return nil, err
	}
	if err := req.Body.Close(); err != nil {
		return nil, err
	}
	rc := req.Clone(req.Context())
	rc.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	rc.ContentLength = n
	rc.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	return rc, nil
}
