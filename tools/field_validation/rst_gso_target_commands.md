# H10 target command and artifact checklist

These are collection templates, not evidence. Save the actual stdout/stderr, packet captures and traces under an operator-controlled artifact directory and index them with `rst_gso_field_validation.py`.

## Code gates

```sh
mkdir -p artifacts
(
  cd src
  go test ./classifier ./nfq ./config ./action ./routing ./crossservice ./sni ./observability ./diagnostics ./runtimecontrol ./http/handler ./capture ./tables ./discovery
) 2>&1 | tee artifacts/go-unit-integration.log

(cd src && go test -race ./classifier ./nfq ./runtimecontrol) 2>&1 | tee artifacts/go-race.log
(cd src && go test ./classifier -run='^$' -fuzz=FuzzTCPReassemblyNeverPanics -fuzztime=30s) 2>&1 | tee artifacts/go-fuzz.log
(cd src && go test ./classifier ./nfq ./action ./runtimecontrol -run='^$' -bench='Benchmark(TCPReassemblyObserve|TCPHoldStoreHoldRelease|ActionTokenClaimSuppress|GenerationFingerprint)$' -benchmem -count=5) 2>&1 | tee artifacts/go-benchmark.log
(cd src/http/ui && pnpm install --frozen-lockfile && pnpm test:classifier) 2>&1 | tee artifacts/ui-contract.log
(cd src && go run tools/gendefaults.go && cd http/ui && pnpm build) 2>&1 | tee artifacts/ui-build.log
```

## Router identity and bounded state

Run before and after each destructive/failure scenario:

```sh
{
  date -u +%FT%TZ
  uname -a
  /opt/etc/b4/b4 --version 2>/dev/null || b4 --version
  cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true
  ip -details -statistics link show
  ip -6 route show
  ip route show
  free -k
  ps w
  iptables-save 2>/dev/null || true
  ip6tables-save 2>/dev/null || true
  nft list ruleset 2>/dev/null || true
} 2>&1 | tee artifacts/router-commands-$(date -u +%Y%m%dT%H%M%SZ).log
```

Capture B4 endpoints separately so failed HTTP calls remain visible in the command log:

```sh
for endpoint in \
  /api/version \
  /api/system/info \
  /api/v2/classifier/config \
  /api/v2/classifier/hardening \
  /api/v2/runtime-control/status \
  /api/observability/metrics \
  /api/diagnostics/issue-bundle
do
  curl --fail-with-body --silent --show-error \
    -H "Authorization: Bearer $B4_API_TOKEN" \
    "https://192.168.1.1:7000${endpoint}"
  printf '\n'
done > artifacts/router-diagnostics.jsonl
```

## Network namespace and GSO lab

Use an isolated host or lab router. Record every command. Replace queue numbers and the B4 invocation with the active hardening topology; do not reuse production LAN queue numbers blindly.

```sh
sudo ip netns add b4gso-client
sudo ip netns add b4gso-server
sudo ip link add b4gso-c type veth peer name b4gso-r
sudo ip link add b4gso-s type veth peer name b4gso-b
sudo ip link set b4gso-c netns b4gso-client
sudo ip link set b4gso-s netns b4gso-server
sudo ip link set b4gso-r up
sudo ip link set b4gso-b up
sudo ip netns exec b4gso-client ip addr add 198.18.0.2/24 dev b4gso-c
sudo ip netns exec b4gso-server ip addr add 198.19.0.2/24 dev b4gso-s
sudo ip netns exec b4gso-client ip link set lo up
sudo ip netns exec b4gso-server ip link set lo up
sudo ip netns exec b4gso-client ip link set b4gso-c up
sudo ip netns exec b4gso-server ip link set b4gso-s up
sudo ip netns exec b4gso-client ethtool -K b4gso-c gso on gro on tso on
sudo ip netns exec b4gso-server ethtool -K b4gso-s gso on gro on tso on
```

A real GSO proof must retain:

- `ethtool -k` output;
- NFQUEUE metadata showing GSO/cap-length/checksum flags;
- pcapng from the relevant pre/post-normalization interfaces;
- command log for queue/rule installation and cleanup;
- metrics snapshots before and after;
- packet/hash comparison for unchanged `NF_ACCEPT`.

Always clean the isolated lab:

```sh
sudo ip netns del b4gso-client 2>/dev/null || true
sudo ip netns del b4gso-server 2>/dev/null || true
sudo ip link del b4gso-r 2>/dev/null || true
sudo ip link del b4gso-b 2>/dev/null || true
```

## Android and Chrome cold-run evidence

Record target model, Android version, app version and monotonic timestamps. Force-stop the selected app between cold runs. Clearing Chrome/app storage is destructive and must be an explicit operator decision, not an automated default.

```sh
adb shell am force-stop com.google.android.youtube
adb shell am force-stop '<revanced package>'
adb logcat -c
adb logcat -v threadtime > artifacts/android-logcat.txt
```

For Chrome DevTools, export a trace/HAR from a fresh profile after DNS, conntrack and B4 runtime state have been reset. Browser completion alone is not correctness proof; correlate it with router milestones and packet captures.

## Passive RST injection evidence

Use a controlled lab injector capable of exact-flow packets. Retain the injector source/version, complete command line and pcapng. Never run forged-RST scenarios against unrelated public traffic. The required matrix includes legitimate closed-port/server-progress resets, forged pre-response resets, burst, TTL/hop-limit, SEQ/ACK, options, no-ACK, unknown flow, incomplete visibility, budgets, generation changes and rollback.
