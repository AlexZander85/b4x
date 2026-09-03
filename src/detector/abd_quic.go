package detector

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type QUICStage string

const (
	QUICQ0UDPReachability    QUICStage = "q0-udp-reachability"
	QUICQ1Initial            QUICStage = "q1-initial"
	QUICQ2VersionNegotiation QUICStage = "q2-version-negotiation"
	QUICQ3Retry              QUICStage = "q3-retry"
	QUICQ4Handshake          QUICStage = "q4-handshake"
	QUICQ5HTTP3Headers       QUICStage = "q5-http3-headers"
	QUICQ6BodyProgress       QUICStage = "q6-body-progress"
	QUICQ7Controls           QUICStage = "q7-controls"
)

type QUICControlKind string

const (
	QUICUDP443Control     QUICControlKind = "udp-443-control"
	QUICTCPControl        QUICControlKind = "tcp-control"
	QUICRandomHostControl QUICControlKind = "random-host-control"
)

type QUICObservation struct {
	Scope         monitor.MonitorScopeKey
	TargetID      string
	IPHash        string
	IPFamily      string
	Fingerprint   FingerprintProfile
	Stage         QUICStage
	Control       QUICControlKind
	Version       string
	RetrySeen     bool
	HTTP3Progress uint64
	Success       bool
	FailureCode   ProbeFailureCode
	ObservedAt    time.Time
}

func (o QUICObservation) Valid() bool {
	return o.Scope.Valid() && o.TargetID != "" && o.IPHash != "" && o.IPFamily != "" && o.Fingerprint != "" && o.Stage != "" && !o.ObservedAt.IsZero()
}

type QUICEvidence struct {
	Scope         monitor.MonitorScopeKey
	TargetID      string
	Observations  []QUICObservation
	TCPComparison []TLSHTTPEvidence
	CreatedAt     time.Time
}

func BuildQUICEvidence(scope monitor.MonitorScopeKey, observations []QUICObservation, tcp []TLSHTTPEvidence, now time.Time) (QUICEvidence, error) {
	if !scope.Valid() || len(observations) == 0 {
		return QUICEvidence{}, errors.New("QUIC evidence requires scoped observations")
	}
	for _, o := range observations {
		if !o.Valid() || o.Scope != scope {
			return QUICEvidence{}, errors.New("invalid or cross-scope QUIC observation")
		}
	}
	return QUICEvidence{Scope: scope, TargetID: observations[0].TargetID, Observations: append([]QUICObservation(nil), observations...), TCPComparison: append([]TLSHTTPEvidence(nil), tcp...), CreatedAt: now}, nil
}
func (e QUICEvidence) ImpliesGlobalUDPBlock() bool {
	var target, control bool
	for _, o := range e.Observations {
		if o.Control == QUICUDP443Control && o.Success {
			control = true
		}
		if o.Control == "" && !o.Success {
			target = true
		}
	}
	return target && !control && len(e.Observations) > 1
}
