# WARP-1 — reference freeze, license, and threat model

The transport track uses a bundled, pinned MASQUE engine contract. Runtime network downloads, floating commits, embedded proxy credentials, and country-guarantee claims are forbidden. Cloudflare/WARP trust is treated as an explicit transport dependency with endpoint, key, privacy, and capability boundaries.

Reference manifests must carry source commit, license notice, source hash, target architecture, and patch-series hash. Build/release tooling must fail on a hash, license, or floating-reference mismatch. Experimental non-RU routing is a liveness/attestation capability, not a country guarantee.

This stage records the threat model and packaging acceptance boundary; implementation stages add the owned manifest, secret, supervisor, route, trace, and validation contracts.

