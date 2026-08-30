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
// The queue orders candidates of the requested location: Load ascending for
// the live list, country-interleaved so the head never comes from a single
// country (the asset ships pre-interleaved and keeps its order offline);
// ports rotate round-robin across candidates [443, 88, 1224, 51820, 500,
// 4500] with a config override pinning ONE port.
package proton

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
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

// sortForQueue orders the node list: live lists rank by Load (ascending,
// ties by Score); the asset (all-zero Load) keeps its order — it is already
// country-interleaved by construction. Either way the result is interleaved
// across countries so the head of the queue never sits in one country.
func (q *Queue) sortForQueue() {
	live := false
	for _, n := range q.nodes {
		if n.Load > 0 {
			live = true
			break
		}
	}
	if live {
		sort.SliceStable(q.nodes, func(i, j int) bool {
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
