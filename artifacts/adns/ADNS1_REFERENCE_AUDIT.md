# ADNS-1 — Reference audit and owner decisions

**Stage:** ADNS-1 of `B4X_POST_V23_ADAPTIVE_DNS_DETECTOR_PATH_CONTROLLER_AND_MANAGED_DNSCRYPT_BACKEND_ADDENDUM_v1.0.md`
**Date:** 2026-08-25
**Status:** DONE (audit record; no runtime code in this stage)

## 1. Pinned references

| Reference | Commit | License | Usage |
|---|---|---|---|
| `UPB-SysSec/DPYProxy` | `28cb05985672275ea96d4083c403739894820375` | Apache-2.0 | Algorithm/reference audit only. **No Python runtime is vendored, imported or executed.** |
| `DNSCrypt/dnscrypt-proxy` | `c3ba78fac8a37fd05c1a4faba77300a9dc03a9dd` | ISC | Optional pinned managed encrypted-DNS backend, supervised by B4X. |

## 2. Source-derived topology correction (owner decision required)

Confirmed from dnscrypt-proxy source capabilities:

- dnscrypt-proxy provides: DNSCrypt v2, PQDNSCrypt, Anonymized DNSCrypt (relays),
  DoH over HTTP/2, DoH over HTTP/3/QUIC (when enabled), ODoH, signed resolver
  sources, cache, performance-aware selection, forced TCP.
- dnscrypt-proxy is **not** a DoT client and **not** a DoQ client.

**Decision recorded:** DoT and DoQ are implemented as **native B4X providers**
or report honest `UNSUPPORTED` / `BLOCKED_BY_CAPABILITY`. They are never
attributed to the dnscrypt-proxy backend. This matches addendum §0.3 and
ADR-ADNS-003.

## 3. LAST_RESPONSE (DPYProxy) — observer only

DPYProxy `LAST_RESPONSE` waits out the UDP window and returns the last
response. In B4X this is accepted **only** as the diagnostic experiment
`UDPResponseRaceObservation`:

- collect all candidate responses in a bounded window;
- validate source tuple, transaction ID, question and message structure;
- retain arrival order and timing;
- compare each response with encrypted/reference paths;
- classify early-injection / duplicate / conflicting / inconclusive;
- **never trust "last" solely because it arrived last.**

Production query path does not implement literal last-answer-wins. Any future
policy of that kind requires a separate owner decision (ADR-ADNS-005).

## 4. Ideas accepted from DPYProxy (implemented natively, deterministically)

- resolver and transport are independent dimensions;
- a working path must be re-confirmed by several attempts;
- TCP segmentation is a separate experiment with on-wire proof requirement;
- UDP response race is observed, not collapsed into first-response result;
- last-good configuration accelerates startup;
- encrypted and unencrypted transports are checked by one normalized matrix.

DPYProxy's random candidate shuffle is **not** carried over: candidate order
is deterministic with canonical `DNSPathID` tie-break (addendum §66).

## 5. Existing B4X DNS code map (production roots)

| Area | Files |
|---|---|
| Structured parser (A/AAAA/CNAME/HTTPS/SVCB, NXDOMAIN, SERVFAIL, TC) | `src/dns/structured.go` |
| Source-scoped correlation | `src/dns/correlation.go` |
| UDP forwarder (mark, fragmentation) | `src/dns/forward.go` |
| DoH wire client (marked, H2) | `src/dns/doh.go` |
| Query builder | `src/dns/query.go` |
| Detector DNS checks | `src/detector/dns.go`, `src/detector/dnsavail.go`, `src/detector/abd_dns.go`, `src/detector/dohwire.go` |
| DDI / prior contract | `src/detector/abd_ddi.go` |
| Discovery | `src/discovery/*` |
| Monitor | `src/monitor/*` |
| Runtime transactions | `src/runtimecontrol/*` |
| Registries | `specs/registries/{hard_gates,principal_verdicts}.yaml` |

New code added by this addendum lives in `src/transport/dns/**` (model,
providers, managed backend, manager) and `src/detector/adns_*.go`
(differential detector / profile compiler). No second Detector, Discovery,
policy daemon or source of truth is created (ADR-ADNS-001/002).

## 6. Owner decisions log

| # | Decision | State |
|---|---|---|
| D1 | DoT/DoQ ownership corrected to native providers | recorded, pending owner sign-off |
| D2 | LAST_RESPONSE accepted as diagnostic observer only | recorded, pending owner sign-off |
| D3 | Managed dnscrypt backend optional, pinned, hash-verified | recorded, pending owner sign-off |
| D4 | Adaptive mode default-off for existing installs | recorded, pending owner sign-off |
