package detector

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type L4Dimension string

const (
	DimensionPacket L4Dimension = "packet"
	DimensionByte   L4Dimension = "byte"
)

type Direction string

const (
	DirectionUplink   Direction = "uplink"
	DirectionDownlink Direction = "downlink"
)

type FreshnessMode string

const (
	FreshFlow      FreshnessMode = "fresh"
	PersistentFlow FreshnessMode = "persistent"
)

type L4Experiment struct {
	Scope       monitor.MonitorScopeKey
	TargetID    string
	Dimension   L4Dimension
	Direction   Direction
	Mode        FreshnessMode
	Packets     uint64
	UniqueBytes uint64
	Success     bool
	ServerLimit bool
	ObservedAt  time.Time
}
type ThresholdInterval struct {
	Dimension             L4Dimension
	Direction             Direction
	Mode                  FreshnessMode
	Lower                 uint64
	Upper                 uint64
	Samples               uint16
	ServerLimitSuppressed bool
	Confidence            float64
}
type L4ThresholdProfile struct {
	Scope     monitor.MonitorScopeKey
	TargetID  string
	Intervals []ThresholdInterval
	CreatedAt time.Time
}

func BuildL4ThresholdProfile(scope monitor.MonitorScopeKey, target string, experiments []L4Experiment, now time.Time) (L4ThresholdProfile, error) {
	if !scope.Valid() || target == "" || len(experiments) == 0 {
		return L4ThresholdProfile{}, errors.New("L4 profile requires scoped experiments")
	}
	r := L4ThresholdProfile{Scope: scope, TargetID: target, CreatedAt: now}
	for _, e := range experiments {
		if e.Scope != scope || e.TargetID != target || e.Dimension == "" || e.Direction == "" || e.Mode == "" || e.ObservedAt.IsZero() {
			return L4ThresholdProfile{}, errors.New("invalid L4 experiment")
		}
		value := e.Packets
		if e.Dimension == DimensionByte {
			value = e.UniqueBytes
		}
		if value == 0 {
			continue
		}
		i := ThresholdInterval{Dimension: e.Dimension, Direction: e.Direction, Mode: e.Mode, Lower: value, Upper: value, Samples: 1, Confidence: .25, ServerLimitSuppressed: e.ServerLimit}
		for j := range r.Intervals {
			p := &r.Intervals[j]
			if p.Dimension == i.Dimension && p.Direction == i.Direction && p.Mode == i.Mode {
				if value < p.Lower {
					p.Lower = value
				}
				if value > p.Upper {
					p.Upper = value
				}
				p.Samples++
				p.Confidence = float64(p.Samples) / float64(p.Samples+2)
				p.ServerLimitSuppressed = p.ServerLimitSuppressed || i.ServerLimitSuppressed
				goto next
			}
		}
		r.Intervals = append(r.Intervals, i)
	next:
	}
	if len(r.Intervals) == 0 {
		return L4ThresholdProfile{}, errors.New("no measurable L4 samples")
	}
	return r, nil
}
func (p L4ThresholdProfile) PacketClaim() bool {
	for _, i := range p.Intervals {
		if i.Dimension == DimensionPacket && !i.ServerLimitSuppressed && i.Confidence >= .5 {
			return true
		}
	}
	return false
}
func (p L4ThresholdProfile) ByteClaim() bool {
	for _, i := range p.Intervals {
		if i.Dimension == DimensionByte && !i.ServerLimitSuppressed && i.Confidence >= .5 {
			return true
		}
	}
	return false
}
