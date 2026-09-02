# NOTICE — transport/fxvpn

## uTLS (FX-M1, owner-approved dependency exception)

The Firefox fingerprint layer (`utfingerprint.go`) vendors
`github.com/refraction-networking/utls v1.8.2` — the same dependency the
Opera reserve transport already carries (`transport/opera/NOTICE.md`).

- **Why**: Go's crypto/tls emits a JA3/JA4 ClientHello no browser produces;
  the review (E-FXVPN chapter 7, §7.4.3/FX-M1) names uTLS as the only
  practical full-mimicry path for the H2 TLS carrier. The Firefox profile
  (`HelloFirefox_Auto`) is materialized as a spec, the ALPN extension is
  swapped for the carrier's `h2` offer, and the hello is sent through a
  `HelloCustom` UConn.
- **Trust model untouched (§7.8 red line)**: uTLS changes the OBSERVED
  BYTES, never the verification. The `VerifyConnection` callback
  (`verifyWebPKIUTLS`) enforces the same WebPKI semantics as the plain-Go
  path — the real node name against the base config's root pool (system
  pool by default; the fake-stand `InsecureSkipVerify` seam behaves
  identically).
- **QUIC scope**: quic-go builds its ClientHello internally and exposes no
  uTLS hook; the QUIC carrier rides the FX-M0 cheap layer (Firefox
  suites/curves, 1250 padding, preflight white-SNI bait). Full QUIC
  mimicry requires the community fork shim — owner decision, precedent
  amneziawg-go v3.
- **Provenance**: upstream https://github.com/refraction-networking/utls,
  BSD-2-Clause; imported as a library, no source modification.

## Embedded roots provenance

The plain-Go and uTLS verification paths use the Go crypto/x509 system
pool (`Roots: nil` semantics) — no root store is embedded in this
package. The fake-stand root pools are test fixtures only and never ship
into production trust decisions.
