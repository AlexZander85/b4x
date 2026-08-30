// Proton profile issuance (design §3.4/§5.3, patch-plan §5.3): the bridge
// between the node catalog (candidates x ports) and the shared transport/wg
// engine (one Profile per candidate). For every candidate the issuer binds:
//
//   - the profile ID: the last-good winner when the store still knows one,
//     otherwise the head of the ladder (config-preferred or proton-quic);
//   - the I1 blob: a REAL QUIC Initial (quici1.go) built from a RANDOM SNI of
//     the pool — only for templates flagged RuntimeI1 (proton-quic); the
//     other families carry static template payloads;
//   - the SNI the blob was built from, for the adaptation log (design §3.4:
//     a degraded profile re-issues with the NEXT pool name, >= 30 min step,
//     implemented by the PT5 health cycle).
//
// The SNI pool: assets/white_sni.txt embedded (90 live-tested names of the
// Nova v1.31 white.sni) with the config override replacing it whole; names
// must not be Proton domains (the obfuscation must not advertise the peer it
// is heading to).
package proton

import (
	_ "embed"
	"io"
	"sort"
	"strings"
	"time"
)

//go:embed assets/white_sni.txt
var whiteSNIAsset string

// DefaultSNIPool parses the embedded white.sni asset: one name per line,
// '#' comments and blank lines skipped. Sorted for deterministic rotation.
func DefaultSNIPool() []string {
	var out []string
	for _, line := range strings.Split(whiteSNIAsset, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.ToLower(strings.TrimSuffix(line, ".")))
	}
	sort.Strings(out)
	return out
}

// ValidSNIName applies the pool admission rules to a config override name:
// a syntactically plausible hostname that is NOT a Proton domain.
func ValidSNIName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" || len(n) > 253 || !strings.Contains(n, ".") {
		return false
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			// RFC 1123 label: alphanumerics and hyphens, no leading/trailing
			// hyphen (kept simple: the pool is owner-controlled).
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	for _, bad := range []string{"proton.me", "protonvpn.ch", "protonmail.ch", "protonpro.xyz", "protonvpn.com", "protonmail.com"} {
		if n == bad || strings.HasSuffix(n, "."+bad) {
			return false
		}
	}
	return true
}

// ProtonProfile is one issued candidate: everything wg.Session needs plus
// the camouflage material.
type ProtonProfile struct {
	Node      Node
	Port      uint16
	ProfileID string // "proton-quic" | ...
	I1        string // hex-chain for InitPacket[0] ("" for static families)
	SNI       string // the pool name the I1 was built from
	IssuedAt  int64
}

// LastGood is the minimal last-good view the issuer consults (satisfied by
// the transportwg LastGoodStore projection in the service).
type LastGood interface {
	LastGoodProfileID() string
}

// memoryLastGood is the trivial in-memory implementation (tests, stateless
// runs); the service wires a persistent one.
type MemoryLastGood struct{ ID string }

func (m *MemoryLastGood) LastGoodProfileID() string { return m.ID }

// IssueProfiles binds one ProtonProfile per candidate: ports and nodes come
// from the candidate list, the profile from the ladder (last-good first when
// it is still a member), the I1 from a random pool draw for RuntimeI1
// templates. Deterministic for a fixed rand — the golden tests pin it.
func IssueProfiles(cands []Candidate, ladder []string, sniPool []string,
	r io.Reader, lastGood LastGood) []ProtonProfile {
	if len(ladder) == 0 {
		ladder = []string{"proton-quic"}
	}
	preferred := ""
	if lastGood != nil {
		preferred = lastGood.LastGoodProfileID()
	}
	pick := func() string {
		if preferred != "" {
			for _, id := range ladder {
				if id == preferred {
					return preferred
				}
			}
		}
		return ladder[0]
	}
	// The pool rotation: shuffle the pool once per issuance (deterministic
	// under the injected rand), so consecutive candidates draw different
	// names without coordinating global state.
	pool := shufflePool(sniPool, r)
	poolIdx := 0
	nextSNI := func() string {
		if len(pool) == 0 {
			return ""
		}
		name := pool[poolIdx%len(pool)]
		poolIdx++
		return name
	}

	out := make([]ProtonProfile, 0, len(cands))
	for _, cand := range cands {
		id := pick()
		p := ProtonProfile{
			Node:      cand.Node,
			Port:      cand.Port,
			ProfileID: id,
			IssuedAt:  time.Now().Unix(),
		}
		if needsRuntimeI1(id) {
			sni := nextSNI()
			p.SNI = sni
			p.I1 = BuildQuicInitial(sni, r)
		}
		out = append(out, p)
	}
	return out
}

// needsRuntimeI1 reports whether the profile template fills I1 at runtime
// (the transportwg ProfileTemplate.RuntimeI1 flag, mirrored here as a name
// check to keep the proton package free of the wg import cycle concerns).
func needsRuntimeI1(id string) bool { return id == "proton-quic" }

// shufflePool returns a deterministically shuffled copy (Fisher-Yates under
// the injected rand); an empty pool stays empty.
func shufflePool(pool []string, r io.Reader) []string {
	out := append([]string(nil), pool...)
	if len(out) < 2 {
		return out
	}
	buf := make([]byte, 1)
	for i := len(out) - 1; i > 0; i-- {
		if _, err := r.Read(buf); err != nil {
			break
		}
		j := int(buf[0]) % (i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return out
}
