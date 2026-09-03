# ABD-5 — TLS/HTTP fingerprint matrix and body progress

The detector records canonical/browser/Android fingerprints, TLS version, HTTP method, certificate verification, staged failure code, attribution, authority, and observer stage. Physical failure codes are not overloaded with causal attribution.

`BodyProgressEvidence` preserves unique bytes and chunk progress through an inter-chunk stall. Headers-only or unsuitable small objects cannot satisfy the media/body milestone or become throttling proof. MITM support requires a verified certificate path and authoritative ABD evidence; passive or unverified alerts remain hypotheses.

Validation: `go test ./detector` passes.

