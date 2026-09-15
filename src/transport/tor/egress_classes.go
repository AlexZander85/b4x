package tor

// ClassPTRendezvous labels active pluggable-transport rendezvous traffic
// (for example Snowflake broker/front requests). Unlike bootstrap-source
// discovery, this traffic is part of the selected PT and therefore must
// inherit the configured egress policy. In particular, a named
// through=<carrier> remains strict/fail-closed instead of silently becoming
// direct-first auto.
const ClassPTRendezvous ConnClass = "pt-rendezvous"
