package warp

import "time"

type GeoClass string

const (
	GeoRU           GeoClass = "ru"
	GeoNonRU        GeoClass = "non-ru"
	GeoUnknown      GeoClass = "unknown"
	GeoDisagreement GeoClass = "disagreement"
)

type GeoObservation struct {
	Provider, PublicIP, PathID string
	Class                      GeoClass
	DNSProof, IPv6Proof        bool
	ObservedAt, ExpiresAt      time.Time
	CounterDelta               uint64
	SessionGeneration          string
}
type GeoAttestation struct {
	Class      GeoClass
	Providers  int
	Quorum     int
	PublicIP   string
	PathID     string
	FreshUntil time.Time
	Revoked    bool
}

func BuildGeoAttestation(obs []GeoObservation, now time.Time) GeoAttestation {
	a := GeoAttestation{}
	counts := map[GeoClass]int{}
	for _, o := range obs {
		if !o.ExpiresAt.IsZero() && !now.Before(o.ExpiresAt) {
			continue
		}
		if o.CounterDelta == 0 || !o.DNSProof {
			continue
		}
		counts[o.Class]++
		if a.PublicIP == "" {
			a.PublicIP = o.PublicIP
			a.PathID = o.PathID
		}
	}
	a.Providers = len(obs)
	a.Quorum = 2
	if counts[GeoNonRU] >= a.Quorum && counts[GeoRU] == 0 && counts[GeoUnknown] == 0 {
		a.Class = GeoNonRU
		a.FreshUntil = now.Add(120 * time.Second)
	} else if counts[GeoRU] > 0 {
		a.Class = GeoRU
		a.Revoked = true
	} else {
		a.Class = GeoDisagreement
		a.Revoked = true
	}
	return a
}
func (a GeoAttestation) Valid(now time.Time) bool {
	return a.Class == GeoNonRU && !a.Revoked && now.Before(a.FreshUntil) && a.PublicIP != "" && a.PathID != ""
}
