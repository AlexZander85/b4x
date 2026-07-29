# Gmail and Google Feed Negative-Control Validation

## Purpose

Prove that enabling the target YouTube sets does not change Gmail, Google app/Discover or unrelated traffic on the same Android device, including when those services share destination IPs.

## Controller flow

1. Prepare a staged runtime candidate and record its pending generation ID.
2. Run Baseline A with target YouTube sets disabled.
3. Run Candidate B with the candidate enabled and no other setting changes.
4. Run Concurrent C with YouTube playback plus Gmail body/content and Google Feed refresh.
5. Run Failure contamination D after a controlled YouTube failure.
6. Complete all fourteen scenario entries listed below.
7. Submit the report to `POST /api/v2/classifier/isolation/validate`.
8. Confirm `promotion_allowed=true` from the report and `GET /api/v2/classifier/isolation`.
9. Promote the pending generation. Promotion is rejected if the exact-generation report is absent, expired or failed.

## Required scenarios

```text
same-client-sequential-shared-ip
same-client-concurrent
two-clients-shared-ip
static-candidate-before-sni
split-reordered-clienthello
ech-scoped-hints
legacy-learned-ip
ipblock-contamination
escalation-contamination
quic-filter-all
route-proxy-binding
hot-apply-rollback
ipv4-ipv6
queue-pressure-incomplete-visibility
```

## Actual-domain capture rule

Do not use a guessed Gmail or Google Feed allowlist as the test oracle. For each observed flow:

- correlate the flow with an app/test milestone;
- collect the actual DNS, packet/reassembled SNI or QUIC provenance;
- normalize and hash the observed hostname locally with SHA-256;
- submit only `domain_hash`, never the raw hostname;
- record the exact config generation and any selected set/action/state;
- never add an unrelated observed domain to a YouTube profile automatically.

The runtime helper `crossservice.HashDomain` documents the canonical normalization. Controllers outside the process should lowercase the hostname, remove a trailing dot and SHA-256 hash the result.

## Minimal report shape

```json
{
  "generation": "<pending generation id>",
  "target_set_ids": ["youtube-api", "youtube-ui", "youtube-video"],
  "max_latency_regression_percent": 20,
  "max_latency_regression_ms": 250,
  "baseline": [
    {
      "flow_id": "<redacted flow id>",
      "service": "gmail",
      "role": "control",
      "milestone": "body-content",
      "domain_hash": "<sha256 hex>",
      "provenance": "dns+sni",
      "config_generation": "baseline",
      "success": true,
      "duration_ms": 900
    }
  ],
  "candidate": [
    {
      "flow_id": "<redacted flow id>",
      "service": "gmail",
      "role": "control",
      "milestone": "body-content",
      "domain_hash": "<sha256 hex>",
      "provenance": "reassembled-sni",
      "config_generation": "<pending generation id>",
      "success": true,
      "duration_ms": 950,
      "actions": []
    },
    {
      "flow_id": "<redacted flow id>",
      "service": "youtube",
      "role": "target",
      "milestone": "video-start",
      "target_class": "video",
      "domain_hash": "<sha256 hex>",
      "provenance": "quic-sni",
      "config_generation": "<pending generation id>",
      "success": true,
      "duration_ms": 700
    }
  ],
  "scenarios": [
    {"id": "same-client-sequential-shared-ip", "passed": true}
  ]
}
```

The complete submission must include Gmail and Google Feed controls, successful YouTube `api`, `ui` and `video` target classes, and all fourteen scenario IDs.

## Action vocabulary

Control-flow `actions` use these machine values:

```text
action_authorization
action_token
packet_mutation
quic_reject
ipblock_hit
escalation
route_proxy_binding
passive_rst_suppression
```

Any such action referencing a target YouTube set is a hard failure. Mark `reused=true` when the state came from a prior flow; cache and route reuse counters must remain zero.

## Field acceptance

The final target report must demonstrate:

- Gmail headers, bodies/content and inline images usable within budget;
- Google Feed initial load, refresh and card/article/image usable within budget;
- official YouTube/ReVanced API, UI and video flows usable;
- no unrelated flow receives a target authorization, token, mutation, QUIC reject, cache state, escalation, route/proxy binding or passive-RST policy;
- exact flow and config-generation correlation in trace.
