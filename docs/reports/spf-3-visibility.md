# SPF-3 — Protocol milestones and visibility gate

Status: IMPLEMENTED_NOT_TARGET_VALIDATED

Added immutable capture capability snapshots and protocol milestones for SYN,
SYN-ACK, ClientHello, ServerHello, first application data, FIN, RST and TLS
Alert. An active configured silent-path mode is degraded to `observe` unless
incoming and outgoing visibility, NFQUEUE health, GSO parity and offload proof
are all current. This layer is evidence-only and cannot change traffic.
