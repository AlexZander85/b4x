# NOTICE — E-PROTON third-party material and provenance

## Embedded data assets (`assets/proton_nodes.json`, `assets/white_sni.txt`)

Both files are DATA (public server facts and a list of public domain names),
NOT code, and ship inside the binary as the offline fallback:

- `proton_nodes.json` — 50 free-tier WireGuard nodes with EXACTLY five
  public fields per node (`server_name`, `country`, `city`, `entry_ip`,
  `peer_public_key`). The peer key is a server PUBLIC key (published by the
  WireGuard protocol itself in every handshake). No account material, no
  private keys, no shared secrets — each device derives and registers its
  own key (the red line the asset invariant test enforces).
- `white_sni.txt` — 90 public domain names used as ClientHello camouflage
  for the QUIC-Initial I1 blob. Names only.

PROVENANCE: extracted from the Nova-Android v1.31 repository (GPL-3.0,
confeden/Nova-Android). These are raw public facts (server catalogs are
published by Proton's own API to any anonymous client; the domain names are
public DNS records). Data is not copyrightable in the relevant
jurisdictions' relevant sense here, and the asset tests make the file
SOURCE-INDEPENDENT: if the owner prefers, the asset can be regenerated from
a live `/vpn/logicals?Tier=0` answer with the same five-field schema without
touching any code (the Nova ProtonNodesAssetTest pattern was ported as
`asset_test.go` exactly for that swap).

## Reference implementation notes

The protocol behavior (credentialless flow, challenge frame, key
conversion, QUIC Initial construction) was ported from study of three
independent implementations (Nova-Android v1.31 GPL-3.0, ProtonVPN-Next
GPL-3.0, proton-vpn-gtk-app GPL). The Go code in this package is a fresh
implementation in this repository's style; no source files were copied
verbatim. Where the references disagreed with RFC 9000/9001 (QUIC Initial
header layout and HKDF labels), the RFC shape was chosen — see the header
comment of `quici1.go` for the three documented deviations.
