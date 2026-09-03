# Cross-Service Isolation Validation Report

## Verdict

`PASS_WITH_FIELD_VALIDATION_REQUIRED`

The implementation and dependency-light tests satisfy the code-level corrective contract. Production promotion remains closed until an exact-generation Gmail/Google Feed negative-control report is submitted and passes on the target device.

## Checks executed

| Check | Result |
|---|---|
| `gofmt` on changed Go files | PASS |
| `git diff --check` | PASS |
| `node src/http/ui/scripts/validate-classifier-ui.mjs` | PASS |
| JSON parse of `classifier.en.json` and `classifier.ru.json` | PASS |
| `GOTOOLCHAIN=local GOPROXY=off go test ./observability ./crossservice` with a temporary local-only Go directive compatibility adjustment | PASS |
| Full project Go suite | BLOCKED: repository requires Go 1.25.3; environment provides Go 1.23.2 and cannot download toolchain/modules |
| Full Vite/TypeScript production build | BLOCKED: frontend dependencies are unavailable in the environment |
| Target Keenetic/Android field matrix | REQUIRED BEFORE PRODUCTION PROMOTION |

The temporary Go directive adjustment was not committed; `src/go.mod` remains at Go 1.25.3.

## Automated hard gates

The validation service rejects promotion when any of the following is observed on a Gmail or Google Feed control flow under a target YouTube set:

- action authorization;
- action token;
- packet mutation;
- QUIC reject;
- IPBlockDetect hit;
- escalation;
- route/proxy binding;
- passive-RST suppression state.

It also requires:

- all fourteen synthetic/field scenario results;
- successful Gmail and Google Feed candidate milestones with successful baseline counterparts;
- candidate latency within the submitted regression budget;
- successful YouTube API, UI and video target classes;
- exact config-generation correlation;
- hashed domain evidence and non-empty DNS/SNI/QUIC provenance;
- zero unrelated actions, cache reuse and route reuse.

## Required machine conditions

```text
unrelated_control_action_total == 0
cross_service_cache_reuse == 0
cross_service_route_reuse == 0
passed_scenarios == required_scenarios == 14
promotion_allowed == true
```

## Failure behavior

A failed or missing report causes the runtime transaction to fail at the promotion stage. The pending generation is rolled back and closed, removed from pending state, placed into cooldown, and retained in bounded history. No automatic domain/IP expansion occurs.
