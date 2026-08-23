# WARP-12 — implementation report

Implemented transport contracts cover bundled engine provenance, protected enrollment, supervisor trace identity, TUN ownership, recursive-route protection, scoped authorization, layered health, camouflage identity/cutoff, candidate selection, nested dependencies, geo quorum, instance isolation, RST observation, product diagnostics, and release gates.

Combined automated validation passes:

```text
go test ./warp ./detector ./discovery ./monitor ./mtproto
```

---

## 2026-08-23 — Data plane engine E0+E1 (bd b4x-ukp; design `.ag/research/warp-dataplane-design.md` v2, owner-approved)

New package `src/transport/warp` (`transportwarp`) — the first real MASQUE/CONNECT-IP data-plane code of this repository (closes the implementation half of B4X-FIX-0004). Zero new external dependencies (stdlib crypto/tls + already-present golang.org/x/net/http2).

Delivered:

| File | Content |
|---|---|
| `catalog.go` | Versioned endpoint catalog (CatalogVersion=1): measured MASQUE gateway map (H2: 162.159.198.0/24 + 199.0/24, v6 103::/48+104::/48; QUIC anycast .1/.2; ports {443,500,1701,4500,4443,8443,8095}). `InCatalog` guard implements addendum §34 "no arbitrary scanning". |
| `varint.go` | RFC 9000 §16 variable-length integers (append/parse/len). |
| `tlsconf.go` | ECDSA P-256 client key lifecycle (usque-compatible base64 SEC1 format), PEM pin parsing, SPKI-SHA256 digest, self-signed 24h client cert, pinned-peer TLS config (insecure forbidden — hard gate masque_insecure_tls stays enforceable), optional extra backend pins (Aether-style rotation tolerance). |
| `dialpolicy.go` + `_linux/_other` | SO_MARK / SO_BINDTODEVICE / source-pin control socket policy (addendum §17–18); constrained policies fail closed on unsupported platforms. |
| `probe.go` | Synthetic IPv4/UDP DNS data-plane probe with full checksums and txid reply matching (Aether validation pattern). |
| `session.go` | H2 CONNECT-IP session: pinned dial to numeric endpoint, CONNECT https://cloudflareaccess.com + cf-connect-proto/pq-enabled headers, capsule DATAGRAM framing both directions, foreign-capsule skip, MTU enforcement, structured failure classes (§62.1 subset), **data-plane trust gate**: 200 is NOT trusted until ValidateDataPlane observes 2 probe round trips in 10 s (refines addendum §29 L2 per design §12); terminal read errors close the session. |
| `fakeserver_test.go` | §66 fake MASQUE server: real h2-over-TLS CONNECT endpoint with behavior matrix (status codes, silent drop, foreign capsules, mid-stream teardown). |

Verification (executed in golang:1.25.3 container):

```text
go vet ./transport/warp/            → clean
go test ./transport/warp/ -count=1  → ok (26 tests)
go test -race                       → ok
go test ./...                       → all green on repo layout (b4-validate/validation need artifacts/ from repo root)
```

§66 scenarios covered offline: TCP refused → tcp-connect-failed; TLS pin mismatch → tls-pin-mismatch; CONNECT 403/429/500 → connect-ip-rejected with status; success echo round trip incl. MTU-size packet; silent-drop after handshake → data-plane-validation-timeout + session teardown; foreign capsule skipping; concurrent writers keep capsule framing; context cancellation honored; oversized packet rejected (ErrPacketTooBig for ICMP TooBig generation at pump level later).

Known gaps to next stages (design E2–E8): enrollment client + identity reconcile, supervisor/backoff/cooldowns, endpoint verification scans, nested warp+warp runtime, non-RU geo gate wiring to warp.BuildGeoAttestation, nfq exclusion-set integration, TUN/PBR field layer. Target-router validation remains BLOCKED_TARGET_VALIDATION.

