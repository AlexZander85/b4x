# E-TOR review fix implementation checkpoint

Target branch for eventual merge: `agent/classifier-v2.3-capture-envelope`.

This checkpoint records the implementation scope derived from `tor-reserve-review.md` before code changes:

- P0: modern Tor relay probe; valid ControlSocket/Socks5Proxy/vanilla torrc; process retirement and ownership guard; strict Snowflake carrier semantics; GETINFO multiline parser; raw bridge control-char rejection; real tor verify-config gate; field-test coverage.
- P1: auto set/meek/RaceWindow semantics; real liveness grace; ranked scanner cohort + persistent scan budget; low-memory Conflux and FD preflight; Snowflake provenance alignment.
- P2: two-stage scanner shape, strict-vs-auto egress contract, bridge-level winner identity, platform capability/status envelope, low-memory Tor profile; conjure/dnstt remain an explicitly separate future stage without new dependencies.

No production behavior is changed by this file.