// GUI projections of the proton control plane (review L6: the former
// service_extras.go split by concern): the locations dropdown view over
// the cached server list.
package proton

import (
	"context"
	"time"
)

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
