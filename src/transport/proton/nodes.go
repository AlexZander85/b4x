// Free-tier node model and the per-location candidate queue (design §5,
// patch-plan §4.1). The free filter is CLIENT-side (design §1.7):
//
//	logical: Tier == 0 && Status == 1
//	physical: Status == 1 && EntryIP != "" && X25519PublicKey != ""
//
// and ONE physical per logical — the Nova rule ("physical servers of one
// logical share the address and the key — take one"), otherwise the list
// bloats with copies.
//
// The queue orders candidates of the requested location: measured TCP/443
// RTT first when available, then Load/Score; countries remain interleaved so
// auto mode does not collapse onto one geography. The RTT is only a ranking
// hint — the AWG/WireGuard trust gate decides whether a node actually works.
// Ports rotate round-robin across candidates [443, 88, 1224, 51820, 500,
// 4500] with a config override pinning ONE port.
package proton

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// ProtonPortCatalog is the vanilla-WG port catalog of the free edge
// (client_config.py:39-49 via the design §1.8 decision).
var ProtonPortCatalog = []uint16{443, 88, 1224, 51820, 500, 4500}

// Node is one connectable free-tier endpoint.
type Node struct {
	Name       string
	Country    string
	City       string
	EntryIP    string
	PeerPubKey string
	Load       int
	Score      float64
	// RTT is an in-process TCP/443 connect sample used only for ordering.
	// It is deliberately not persisted in serverlist.json: a stale network
	// measurement must not survive a process/network change.
	RTT time.Duration `json:"-"`
}

// AddrPort renders the node onto the WG endpoint for port.
func (n Node) AddrPort(port uint16) netip.AddrPort {
	ip, err := netip.ParseAddr(n.EntryIP)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip, port)
}

// Location selects the serving scope (config mirror of
// config.ProtonLocation; PT6 converts).
type Location struct {
	Mode    string // auto | country | host
	Country string
	Host    string
}

// Normalize lowercases the mode.
func (l Location) Normalize() Location {
	l.Mode = strings.ToLower(strings.TrimSpace(l.Mode))
	return l
}

// ValidateLocation checks a requested location against the current node set
// (mode-specific required fields + InCatalog membership — the
// fxvpservice.ValidateLocation canon).
func ValidateLocation(loc Location, nodes []Node) error {
	switch strings.ToLower(loc.Mode) {
	case "", "auto":
		return nil
	case "country":
		if strings.TrimSpace(loc.Country) == "" {
			return fmt.Errorf("%w: country required for mode=country", ErrNoNodes)
		}
		for _, n := range nodes {
			if strings.EqualFold(n.Country, loc.Country) {
				return nil
			}
		}
		return fmt.Errorf("%w: country %q not in the node catalog", ErrNoNodes, loc.Country)
	case "host":
		if strings.TrimSpace(loc.Host) == "" {
			return fmt.Errorf("%w: host required for mode=host", ErrNoNodes)
		}
		for _, n := range nodes {
			if strings.EqualFold(n.Name, loc.Host) || n.EntryIP == loc.Host {
				return nil
			}
		}
		return fmt.Errorf("%w: host %q not in the node catalog", ErrNoNodes, loc.Host)
	default:
		return fmt.Errorf("proton: location.mode %q invalid (auto|country|host)", loc.Mode)
	}
}

// Candidate is one seek target: a node bound to a concrete port.
type Candidate struct {
	Node Node
	Port uint16
}

// AddrPort renders the candidate endpoint.
func (c Candidate) AddrPort() netip.AddrPort { return c.Node.AddrPort(c.Port) }

// Queue is the candidate queue of one location snapshot.
type Queue struct {
	nodes []Node
	ports []uint16
	// rr advances by len(candidates) on every Candidates() call so the next
	// invocation starts the port rotation one step further (Nova's
	// "round-robin the profiles across ports" pattern).
	rr int
}

// NewQueue builds the queue; portOverride != 0 pins ONE port for every
// candidate (config override), otherwise the catalog rotates.
func NewQueue(nodes []Node, portOverride uint16) *Queue {
	q := &Queue{nodes: append([]Node(nil), nodes...)}
	if portOverride != 0 {
		q.ports = []uint16{portOverride}
	} else {
		q.ports = append([]uint16(nil), ProtonPortCatalog...)
	}
	q.sortForQueue()
	return q
}

// sortForQueue orders the node list. When RTT samples exist, measured nodes
// are preferred and lower RTT wins; Load/Score are tie-breakers. Without RTT
// the historical Load/Score behavior is unchanged. The asset (all-zero Load,
// no RTT) keeps its authored order. The final country interleave preserves
// geographic diversity in auto mode while retaining RTT order inside each
// country.
func (q *Queue) sortForQueue() {
	hasRTT := false
	live := false
	for _, n := range q.nodes {
		if n.RTT > 0 {
			hasRTT = true
		}
		if n.Load > 0 {
			live = true
		}
	}
	if hasRTT || live {
		sort.SliceStable(q.nodes, func(i, j int) bool {
			ri, rj := q.nodes[i].RTT, q.nodes[j].RTT
			if ri > 0 || rj > 0 {
				if (ri > 0) != (rj > 0) {
					return ri > 0
				}
				if ri != rj {
					return ri < rj
				}
			}
			if q.nodes[i].Load != q.nodes[j].Load {
				return q.nodes[i].Load < q.nodes[j].Load
			}
			return q.nodes[i].Score < q.nodes[j].Score
		})
	}
	q.nodes = interleaveByCountry(q.nodes)
}

// interleaveByCountry round-robins the nodes across their countries (CA, US,
// NL, NO, CA, US, ...): the candidate head diversifies geographically even
// when one country dominates the list.
func interleaveByCountry(nodes []Node) []Node {
	byCountry := map[string][]Node{}
	var countries []string
	for _, n := range nodes {
		c := strings.ToUpper(n.Country)
		if _, ok := byCountry[c]; !ok {
			countries = append(countries, c)
		}
		byCountry[c] = append(byCountry[c], n)
	}
	out := make([]Node, 0, len(nodes))
	// Countries keep their first-appearance order; each round takes one node
	// per still-non-empty country.
	for len(out) < len(nodes) {
		progressed := false
		for _, c := range countries {
			if len(byCountry[c]) > 0 {
				out = append(out, byCountry[c][0])
				byCountry[c] = byCountry[c][1:]
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// Candidates returns the filtered, ordered candidate list for the location.
// Every node yields its port from the round-robin rotation.
func (q *Queue) Candidates(loc Location) []Candidate {
	loc = loc.Normalize()
	var selected []Node
	switch loc.Mode {
	case "country":
		for _, n := range q.nodes {
			if strings.EqualFold(n.Country, loc.Country) {
				selected = append(selected, n)
			}
		}
	case "host":
		for _, n := range q.nodes {
			if strings.EqualFold(n.Name, loc.Host) || n.EntryIP == loc.Host {
				selected = append(selected, n)
			}
		}
	default: // auto / empty
		selected = q.nodes
	}
	out := make([]Candidate, 0, len(selected))
	for i, n := range selected {
		out = append(out, Candidate{Node: n, Port: q.ports[(q.rr+i)%len(q.ports)]})
	}
	q.rr += len(selected)
	return out
}

// portFallbacksPerNode is the Nova 1.32.3 expandPortFallbacks canon: the
// TOP nodes of each country get extra ports ("блокируют и порт, и адрес,
// замер UDP-порта нечем проверить, попытка подключения — единственная
// проверка"). A node whose primary port is filtered still answers on the
// next one; the cost is a few extra seek attempts, bounded per country.
const portFallbacksPerNode = 3

// countryTopCount limits HOW MANY nodes per country carry the fallback
// ports (Nova: top-2 of each country).
const countryTopCount = 2

// candidatePair is one node's primary candidate plus its ordered fallback
// ports (the seek expansion unit).
type candidatePair struct {
	cand  Candidate
	ports []uint16 // fallback ports in catalog-rotation order (primary rides in cand)
}

// CandidatesOrdered is the seek-order-aware variant of Candidates (Nova
// 1.32.3 connectOrder):
//
//   - every node keeps its round-robin primary port; the top
//     countryTopCount nodes of each country additionally carry
//     portFallbacksPerNode-1 fallback ports (the next catalog entries);
//   - with a non-nil OutcomeMemory the pairs are re-ordered into the
//     proven / fresh / failed address tiers: proven addresses (last
//     success newer than last failure) lead with ONE pair each, freshest
//     first; failure-free addresses follow breadth-first (first port of
//     every address, then the second); failed addresses close the list
//     oldest-failure-first, so each retry wave starts on a different node;
//   - a nil OutcomeMemory degrades to the expansion ordering only (tier
//     collapse) — the call is still deterministic.
//
// The rr rotation advances exactly like Candidates so the two entry points
// stay interchangeable for the port window.
func (q *Queue) CandidatesOrdered(loc Location, om *OutcomeMemory) []Candidate {
	loc = loc.Normalize()
	var selected []Node
	switch loc.Mode {
	case "country":
		for _, n := range q.nodes {
			if strings.EqualFold(n.Country, loc.Country) {
				selected = append(selected, n)
			}
		}
	case "host":
		for _, n := range q.nodes {
			if strings.EqualFold(n.Name, loc.Host) || n.EntryIP == loc.Host {
				selected = append(selected, n)
			}
		}
	default: // auto / empty
		selected = q.nodes
	}
	q.rr += len(selected)
	if len(selected) == 0 {
		return nil
	}

	// Per-country head counter: the first countryTopCount nodes of each
	// country (in queue order — already load-ranked and interleaved) get
	// the fallback ports.
	countrySeen := map[string]int{}
	pairs := make([]candidatePair, 0, len(selected)*2)
	for i, n := range selected {
		primary := q.ports[(q.rr-len(selected)+i)%len(q.ports)]
		p := candidatePair{cand: Candidate{Node: n, Port: primary}}
		if idx := countrySeen[strings.ToUpper(n.Country)]; idx < countryTopCount && len(q.ports) > 1 {
			for k := 1; k < portFallbacksPerNode; k++ {
				p.ports = append(p.ports, q.ports[(q.rr-len(selected)+i+k)%len(q.ports)])
			}
		}
		countrySeen[strings.ToUpper(n.Country)]++
		pairs = append(pairs, p)
	}

	if om == nil {
		// No memory: flat order, primary ports first then fallbacks
		// breadth-first (a fallback never precedes a primary).
		return flattenBreadthFirst(pairs)
	}
	now := om.now()
	type tiered struct {
		p    candidatePair
		tier outcomeTier
		sn   OutcomeSnapshot
	}
	tieredPairs := make([]tiered, 0, len(pairs))
	for _, p := range pairs {
		sn, ok := om.Lookup(p.cand.Node.EntryIP)
		tieredPairs = append(tieredPairs, tiered{p: p, tier: tierOf(sn, ok, now), sn: sn})
	}
	sort.SliceStable(tieredPairs, func(i, j int) bool {
		a, b := tieredPairs[i], tieredPairs[j]
		if a.tier != b.tier {
			return a.tier < b.tier
		}
		switch a.tier {
		case tierProven:
			// Freshest success first: a working node keeps the head.
			return a.sn.LastSuccess.After(b.sn.LastSuccess)
		case tierFailed:
			// Oldest failure first: the next wave starts elsewhere.
			return a.sn.LastFailure.Before(b.sn.LastFailure)
		}
		return false // tierFresh: keep queue order (stable)
	})

	// Tier 1 emits ONE pair per address (the primary port); the rest of
	// every tier flows breadth-first across the port axis.
	var out []Candidate
	seenProven := map[string]bool{}
	var rest []candidatePair
	for _, tp := range tieredPairs {
		if tp.tier == tierProven && !seenProven[tp.p.cand.Node.EntryIP] {
			seenProven[tp.p.cand.Node.EntryIP] = true
			out = append(out, tp.p.cand)
			if len(tp.p.ports) > 0 {
				rest = append(rest, tp.p)
			}
			continue
		}
		rest = append(rest, tp.p)
	}
	return append(out, flattenBreadthFirst(rest)...)
}

// flattenBreadthFirst emits the primary pairs of every entry first, then
// the fallback ports layer by layer (Nova: "сначала 1-й порт каждого
// адреса, потом 2-й" — a backup port never buries another address's
// primary).
func flattenBreadthFirst(pairs []candidatePair) []Candidate {
	out := make([]Candidate, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.cand)
	}
	for depth := 0; ; depth++ {
		emitted := false
		for _, p := range pairs {
			if depth < len(p.ports) {
				out = append(out, Candidate{Node: p.cand.Node, Port: p.ports[depth]})
				emitted = true
			}
		}
		if !emitted {
			return out
		}
	}
}

// Len reports the queue size (status ProfilesLeft counting).
func (q *Queue) Len() int { return len(q.nodes) }

// FreeNodes applies the client-side free filter to a logicals response and
// reduces it to one Node per logical (first valid physical).
func FreeNodes(resp *LogicalsResponse) []Node {
	if resp == nil {
		return nil
	}
	out := make([]Node, 0, len(resp.LogicalServers))
	for _, l := range resp.LogicalServers {
		if l.Tier != 0 || l.Status != 1 {
			continue
		}
		for _, p := range l.Servers {
			if p.Status != 1 || p.EntryIP == "" || p.X25519PublicKey == "" {
				continue
			}
			name := l.Name
			if name == "" {
				name = "PROTON"
			}
			country := l.ExitCountry
			if country == "" {
				country = "??"
			}
			out = append(out, Node{
				Name:       name,
				Country:    country,
				City:       l.City,
				EntryIP:    p.EntryIP,
				PeerPubKey: p.X25519PublicKey,
				Load:       l.Load,
				Score:      l.Score,
			})
			break // one physical per logical
		}
	}
	return out
}
