// b4x fork (design E-TOR §10): the SQS rendezvous is REMOVED. The
// aws-sdk-go-v2 tree it drags into vendor is unacceptable for the MIPS
// router images, and the upstream paths call log.Fatalln — a process
// killer for an embedding program. Bridge lines carrying sqsqueue=/
// sqscreds= are rejected at the b4x parser layer BEFORE any client is
// built; this stub keeps the internal call sites compiling and fails
// loudly if they are ever reached anyway.
package snowflake_client

import (
	"fmt"
	"net/http"
)

type sqsRendezvous struct {
	transport http.RoundTripper
}

func newSQSRendezvous(sqsQueue string, sqsCredsStr string, transport http.RoundTripper) (*sqsRendezvous, error) {
	return nil, fmt.Errorf("snowflake b4x fork: SQS rendezvous removed (sqsqueue/sqscreds lines are rejected at the parser)")
}

// Exchange satisfies the RendezvousMethod interface; it is unreachable
// through the b4x configuration surface.
func (r *sqsRendezvous) Exchange([]byte) ([]byte, error) {
	return nil, fmt.Errorf("snowflake b4x fork: SQS rendezvous removed")
}
