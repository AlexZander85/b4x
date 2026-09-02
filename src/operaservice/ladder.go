// Masquerade ladder (review E-OPERA §7.5, stage OP-M4) — the Seeker/last-good
// analog for the TCP/TLS transport. Rungs from the FULL browser masquerade
// down to the historical plain-Go behavior:
//
//	[0] browser + node-SNI + ALPN + resumption + uTLS   # full masquerade
//	[1] browser + pool-SNI                              # node names get cut by SNI
//	[2] browser + no-SNI                                # the pool is blocklisted too
//	[3] plain-Go + node-SNI                             # the uTLS layer broke / rollback
//	[4] plain-Go + no-SNI                               # the historical bottom rung
//
// plus the ttl_fake/NFQ bait as the INDEPENDENT orthogonal layer (§7.4.3).
//
// Triggers: CONFIRMED data-plane failure classes only — TLS failures with
// a live TCP dial (RST after ClientHello / hello-drop classification) step
// DOWN after three consecutive episodes; everything else (timeouts with a
// dead dial, credential refusals, region unavailability) belongs to other
// machinery and must not move the ladder. Steps UP happen one rung per
// cooldown (300s program canon) after a quiet streak — anti-oscillation:
// one episode, one switch (fxvpn ladder.go canon).
//
// Every switch is OBSERVABLE (§7.8.5): opera_masquerade_switched event in
// the status ring + the opera_masquerade_switched_total counter, and the
// winning rung persists as last-good (identity-slot discipline) so a
// reboot resumes the field-proven rung.
package operaservice

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/observability"
	opera "github.com/daniellavrushin/b4/transport/opera"
)

// LadderCooldown is the anti-oscillation step-up delay (program canon:
// fxvpn ladder and health cooldown share the 300s figure).
const LadderCooldown = 300 * time.Second

// LadderFailLimit is the consecutive confirmed-failure count that steps the
// ladder DOWN (mirrors the health layer's FailureLimit figure).
const LadderFailLimit = 3

// LadderQuietStreak is the consecutive successful dials required on top of
// the cooldown before stepping UP (one episode, one switch — no flapping).
const LadderQuietStreak = 5

// ladderRung is one masquerade configuration of the ladder.
type ladderRung struct {
	name        string
	profile     opera.MasqueradeProfile
	sniMode     opera.SNIMode
	fingerprint string
}

// masqueradeLadderRungs is the §7.5 ladder, top (most masked) first.
var masqueradeLadderRungs = []ladderRung{
	{name: "browser+node-sni", profile: opera.MasqueradeBrowser, sniMode: opera.SNIModeNode, fingerprint: opera.FingerprintChrome120},
	{name: "browser+pool-sni", profile: opera.MasqueradeBrowser, sniMode: opera.SNIModePool, fingerprint: opera.FingerprintChrome120},
	{name: "browser+no-sni", profile: opera.MasqueradeBrowser, sniMode: opera.SNIModeNone, fingerprint: opera.FingerprintChrome120},
	{name: "plain+node-sni", profile: opera.MasqueradeMinimal, sniMode: opera.SNIModeNode, fingerprint: opera.FingerprintNone},
	{name: "plain+no-sni", profile: opera.MasqueradeMinimal, sniMode: opera.SNIModeNone, fingerprint: opera.FingerprintNone},
}

// masqueradeLadder drives the rung state machine.
type masqueradeLadder struct {
	box   *opera.MasqueradeBox
	ring  *eventRing
	store *LadderStore

	// headRung is the CEILING the config profile chose: the ladder never
	// steps above it (owner intent — review §7.5 "старт с верхней ступени").
	headRung int

	pool    []string // configured sni_pool (rung-independent config)
	ttlFake bool     // bait flag rides every rung (rung-independent config)

	mu            sync.Mutex
	idx           int
	consecFails   int
	quietStreak   int
	stepUpAt      time.Time
	now           func() time.Time
	lastGoodSaved string
}

// newMasqueradeLadder resolves the starting rung: the last-good rung when
// it is still within the ladder and not above the configured ceiling;
// otherwise the ceiling itself.
func newMasqueradeLadder(box *opera.MasqueradeBox, ring *eventRing, store *LadderStore, headRung int, pool []string, ttlFake bool, now func() time.Time) *masqueradeLadder {
	if now == nil {
		now = time.Now
	}
	if headRung < 0 || headRung >= len(masqueradeLadderRungs) {
		headRung = 0
	}
	l := &masqueradeLadder{box: box, ring: ring, store: store, headRung: headRung, now: now, pool: pool, ttlFake: ttlFake}
	idx := headRung
	if store != nil {
		if name, ok := store.Get(); ok {
			// The ceiling is the MOST masked rung (lowest index); every
			// rung BELOW it (higher index) is a legitimate restore.
			if i := ladderRungIndex(name); i >= headRung {
				idx = i
			}
		}
	}
	l.idx = idx
	l.apply(l.currentRung(), pool)
	return l
}

func ladderRungIndex(name string) int {
	for i, r := range masqueradeLadderRungs {
		if r.name == name {
			return i
		}
	}
	return -1
}

func (l *masqueradeLadder) currentRung() ladderRung {
	return masqueradeLadderRungs[l.idx]
}

// apply folds a rung into MasqueradeSettings (the pool rides along — it is
// rung-independent configuration) and pushes it into the box.
func (l *masqueradeLadder) apply(rung ladderRung, _ []string) {
	res := opera.ResolveMasquerade(string(rung.profile), string(rung.sniMode), l.pool, nil, nil, l.ttlFake)
	res.Fingerprint = rung.fingerprint
	l.box.Set(res)
}

// ObserveDial feeds one data-plane dial outcome into the state machine.
// Returns the new rung name and direction when a switch happened.
func (l *masqueradeLadder) ObserveDial(ok bool, err error) (from, to, direction string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	if ok {
		l.consecFails = 0
		l.quietStreak++
		// Step UP: cooldown expired + quiet streak + head not reached.
		if l.idx > l.headRung && !l.stepUpAt.IsZero() && now.After(l.stepUpAt) &&
			l.quietStreak >= LadderQuietStreak {
			from, to, direction = l.step(now, -1, "quiet-streak")
		}
		return from, to, direction
	}

	l.quietStreak = 0
	if !isLadderSwitchClass(err) {
		return from, to, direction
	}
	l.consecFails++
	if l.consecFails >= LadderFailLimit && l.idx < len(masqueradeLadderRungs)-1 {
		from, to, direction = l.step(now, +1, "confirmed-block")
	}
	return from, to, direction
}

// step moves the ladder by delta (clamped to the head/floor) and applies
// the new rung.
func (l *masqueradeLadder) step(now time.Time, delta int, cause string) (from, to, direction string) {
	next := l.idx + delta
	if next < l.headRung {
		next = l.headRung
	}
	if next >= len(masqueradeLadderRungs) {
		next = len(masqueradeLadderRungs) - 1
	}
	if next == l.idx {
		return "", "", ""
	}
	fromRung := l.currentRung()
	l.idx = next
	toRung := l.currentRung()
	l.apply(toRung, nil)
	l.consecFails = 0
	l.quietStreak = 0
	if delta > 0 {
		// Just stepped DOWN: the step-up cooldown starts now.
		l.stepUpAt = now.Add(LadderCooldown)
	} else {
		l.stepUpAt = time.Time{}
	}
	direction = "down"
	if delta < 0 {
		direction = "up"
	}

	detail := fromRung.name + " -> " + toRung.name + " (" + cause + ")"
	if l.ring != nil {
		l.ring.append(EventMasqueradeSwitched, detail)
	}
	observability.Default().Metrics.Inc(observability.MetricOperaMasqueradeSwitched,
		map[string]string{"direction": direction, "from": fromRung.name, "to": toRung.name}, 1)

	// last-good: the field-proven rung survives a reboot.
	if l.store != nil {
		if err := l.store.Put(toRung.name); err == nil {
			l.lastGoodSaved = toRung.name
		}
	}
	return fromRung.name, toRung.name, direction
}

// isLadderSwitchClass filters CONFIRMED data-plane block classes (review
// §7.5: RST storm after ClientHello = TLS failure with a live dial;
// CONNECT-timeout on fresh sessions with a live dial). Everything else —
// credential refusals, region unavailability, plain network death —
// belongs to the health machinery and must NOT move the ladder.
func isLadderSwitchClass(err error) bool {
	if err == nil {
		return false
	}
	// TLS failures with a LIVE TCP dial (the dialer attached, then the
	// hello got RST/dropped) — the strongest hello-fingerprint signature.
	return opera.IsClass(err, opera.ClassDataPlaneTLS)
}

// ---------------------------------------------------------------------------
// Last-good store (transportwg.FileLastGood canon: temp+fsync+rename,
// corrupt quarantined).
// ---------------------------------------------------------------------------

// LadderStore persists the winning rung name.
type LadderStore struct {
	Path string
}

type ladderStoreFile struct {
	Rung string `json:"rung"`
}

// Get returns the persisted rung name.
func (s *LadderStore) Get() (string, bool) {
	if s == nil || s.Path == "" {
		return "", false
	}
	blob, err := os.ReadFile(s.Path)
	if err != nil {
		return "", false
	}
	var rec ladderStoreFile
	if err := json.Unmarshal(blob, &rec); err != nil {
		_ = os.Rename(s.Path, s.Path+".corrupt")
		return "", false
	}
	if rec.Rung == "" {
		return "", false
	}
	return rec.Rung, true
}

// Put persists the rung atomically.
func (s *LadderStore) Put(rung string) error {
	if s == nil || s.Path == "" {
		return errors.New("operaservice: ladder store path empty")
	}
	blob, err := json.Marshal(ladderStoreFile{Rung: rung})
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".opera-ladder-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if _, err := tmp.Write(blob); err != nil {
		cleanup()
		return err
	}
	_ = tmp.Chmod(0o600)
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.Path)
}
