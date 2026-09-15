module github.com/daniellavrushin/b4

go 1.25.3

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/klauspost/reedsolomon v1.12.4 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/miekg/dns v1.1.65 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pion/datachannel v1.6.0 // indirect
	github.com/pion/dtls/v3 v3.1.2 // indirect
	github.com/pion/ice/v4 v4.2.0 // indirect
	github.com/pion/interceptor v0.1.43 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/rtp v1.10.1 // indirect
	github.com/pion/sctp v1.9.2 // indirect
	github.com/pion/sdp/v3 v3.0.17 // indirect
	github.com/pion/srtp/v3 v3.0.10 // indirect
	github.com/pion/stun/v3 v3.1.1 // indirect
	github.com/pion/turn/v4 v4.1.4 // indirect
	github.com/pion/webrtc/v4 v4.2.3-securityfix // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/realclientip/realclientip-go v1.0.0 // indirect
	github.com/theodorsm/covert-dtls v1.5.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/txthinking/runnergroup v0.0.0-20241229123329-7b873ad00768 // indirect
	github.com/txthinking/socks5 v0.0.0-20251011041537-5c31f201a10e // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/xtaci/kcp-go/v5 v5.6.24 // indirect
	github.com/xtaci/smux v1.5.56 // indirect
	gitlab.com/yawning/edwards25519-extra v0.0.0-20231005122941-2149dcafc266 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil v0.0.0-20250815012447-418f76dcf315 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel v0.0.3 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

require (
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814
	github.com/florianl/go-nfqueue v1.3.2
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/josharian/native v1.1.0
	github.com/mdlayher/netlink v1.7.2
	github.com/pion/transport/v4 v4.1.1
	github.com/quic-go/quic-go v0.61.0
	github.com/refraction-networking/utls v1.8.2
	github.com/spf13/cobra v1.10.1
	github.com/spf13/pflag v1.0.10
	github.com/urlesistiana/v2dat v0.0.0-20221215035016-47b8ee51fb52
	github.com/yl2chen/cidranger v1.0.2
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.6.0
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird v0.0.0-20260806110331-2e288a7e60a3
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2 v2.14.1
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.56.0
	golang.org/x/sys v0.47.0
	google.golang.org/protobuf v1.36.8
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489
)

// b4x fork: uTLS ClientHello seam for QUIC clients (Config.UTLSClientHelloID).
replace github.com/quic-go/quic-go => github.com/AlexZander85/quic-go v0.61.0-b4x.2

// E-TOR (design §10 — the sanctioned dependency exception): pluggable
// transports as in-process libraries. The snowflake fork lives at
// tools/snowflake (2 changes against v2.14.1, see
// tools/deps/patches/snowflake-b4x.patch): socket hooks
// (NetWrapper/BrokerDialContext) + SQS rendezvous removal (drops the
// aws-sdk-go-v2 vendor tree for MIPS images).
replace gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2 => ../tools/snowflake
