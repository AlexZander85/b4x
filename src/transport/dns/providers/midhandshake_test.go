package providers

import (
	"errors"
	"fmt"
	"io"
	"syscall"
	"testing"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

func TestOutcomeFromErrorMidHandshakeReset(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want dnspath.OutcomeClass
	}{
		{"conn reset", syscall.ECONNRESET, dnspath.OutcomeTLSMidHandshakeReset},
		{"wrapped conn reset", fmt.Errorf("read tcp: %w", syscall.ECONNRESET), dnspath.OutcomeTLSMidHandshakeReset},
		{"unexpected EOF", io.ErrUnexpectedEOF, dnspath.OutcomeTLSMidHandshakeReset},
		{"tls unexpected eof string", errors.New("tls: unexpected EOF while reading"), dnspath.OutcomeTLSMidHandshakeReset},
		{"conn refused stays refused", syscall.ECONNREFUSED, dnspath.OutcomeConnectionRefused},
		{"unknown stays inconclusive", errors.New("weird failure"), dnspath.OutcomeInconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := outcomeFromError(tc.err); got != tc.want {
				t.Fatalf("outcomeFromError(%v) = %s, want %s", tc.err, got, tc.want)
			}
		})
	}
}
