# NOTICE — E-OPERA third-party material and provenance

## Vendored dependency: `github.com/refraction-networking/utls` v1.8.2

Added with the OWNER'S EXPLICIT APPROVAL (review E-OPERA §7.4.2 stage
OP-M1; red line §7.8.2 names uTLS as the sanctioned dependency exception).

WHY: the Opera reserve transport is TLS-over-TCP, so the ClientHello IS
the observable payload — and Go's crypto/tls emits a JA3/JA4 fingerprint
matching no browser. uTLS produces a byte-accurate Chrome ClientHello
while keeping the custom `VerifyConnection` path, which is what allows the
masquerade to change OBSERVED BYTES without touching the trust model
(§7.4.0 red line: TOFU pin for the API channel, WebPKI + real node name
against the embedded Mozilla/NSS pool for the data plane).

License: BSD-3-Clause (upstream LICENSE vendored alongside the code).
Upstream: https://github.com/refraction-networking/utls
Consumers: `src/transport/opera/utfingerprint.go` (fingerprint presets +
dial), `src/transport/opera/h2tunnel.go` (rides the fingerprinted TLS),
`src/transport/opera/masquerade.go` (fingerprint identifiers).

Transitive additions pulled by the vendoring pass: `brotli`
(andybalholm/brotli, MIT), `klauspost/compress` (Apache-2.0), and the
`golang.org/x/crypto/sha3` files from the already-shipped x/crypto module
— all vendored under their own licenses in `src/vendor/`.

## Embedded data asset: `transport/opera/assets/roots.pem`

Mozilla/NSS root CA set (PEM, public data — published by Mozilla and every
Linux distribution):

- USERTrust ECC Certification Authority (the design-named anchor for the
  sec-tunnel node chains)
- USERTrust RSA Certification Authority
- AAA Certificate Services (Comodo legacy)
- Sectigo Public Server Authentication Root E46 / R46

These are raw public trust anchors (not copyrightable data); they close
review H1 — routers without the OS `ca-certificates` package still verify
node chains, and a structurally empty pool fails closed with the
dedicated `opera-dataplane-no-roots` class instead of a silent dead end.

## White-SNI pool (masquerade `sni_pool`)

The shipping default is EMPTY: the node SNI discipline (§7.4.1) sends the
REAL node name, which needs no third-party data. An owner-configured pool
is validated as RFC 1123 hostnames and must not contain `sec-tunnel.com`
names. The optional reference list lives with the proton transport
(`transport/proton/assets/white_sni.txt`) — data, not code.
