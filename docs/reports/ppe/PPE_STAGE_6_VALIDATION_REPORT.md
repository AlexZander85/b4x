# PPE Stage 6 Validation Report

## Verdict

PASS_WITH_LIMITATIONS

## Local validation

- `go test ./...` in a dependency-free PPE-6 harness: PASS.
- `go test -race ./...`: PASS.
- `go vet ./...`: PASS.
- Strict controlled endpoint protocol acceptance/rejection tests: PASS.
- A/B contrast required for `PASS`: PASS.
- Complete visibility without contrast returns `PASS_WITH_LIMITATIONS`: PASS.
- Healthy endpoint plus incomplete B phase returns `FAIL`: PASS.
- Unhealthy endpoint returns `INCONCLUSIVE`: PASS.
- Unsupported capability returns `UNSUPPORTED`: PASS.
- Bounded result-store eviction and clone tests: PASS.
- Observation subscription/unsubscription test: PASS.

## Deferred target validation

The following cannot be claimed without a controlled Keenetic/MediaTek run:

- actual split ClientHello packet visibility;
- same-sequence retransmission visibility;
- incoming ServerHello/ACK/RST visibility;
- QUIC response visibility;
- real PPE rule-counter contrast;
- proof that unrelated bulk traffic remains accelerated.

Therefore this stage does not enable automatic promotion by itself.
