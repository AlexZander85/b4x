# PPE Implementation Audit

## Scope

This audit covers the B4 tree after the v2.3 Stage 36 validation harness and transactional runtime-control prerequisite. It is the mandatory pre-implementation audit for the Keenetic MediaTek PPE per-flow offload addendum.

## Current firewall path

- `tables.AddRules` selects nftables or iptables and owns the normal B4 capture/routing rules.
- The iptables path creates `B4` and `B4_PREROUTING`; outgoing forwarding is reached through `POSTROUTING` or device-scoped `FORWARD`, while incoming/DNS/TCP progress is queued from `PREROUTING`.
- `tables.Monitor` periodically verifies the B4 chains/jumps and restores the full ruleset when they disappear.
- `tables.linkWatcher` handles interface changes, but it is not an NDM netfilter regeneration hook.
- Keenetic NDM can rebuild mangle tables independently of link state. The existing periodic monitor is therefore a useful safety net, not a sufficient event-driven PPE lifecycle.

## Current offload behavior

- `capture.EvaluateOffload` is deliberately conservative and can report suspected bypass from queue/progress observations.
- B4 does not currently install native `-j PPE` rules, test `connskip`, maintain a bounded per-flow CPU window, or distinguish static capability from functional bidirectional visibility.
- `detectFlowOffload` reports global flow-offload metadata only. It cannot prove that the relevant forwarded handshake packets remain visible.

## Capture, marks, and raw sender interaction

- Original packets are queued through NFQUEUE and accepted/replaced by workers.
- B4 uses a processed-packet mark contract from `packetmark`/`capture` to prevent generated packets from re-entering the normal action path.
- Transactional canary steering owns separate flow/direct marks and isolated candidate queues.
- PPE rules must not write CONNMARK, must not reuse processed/candidate marks, and must run before hardware binding without bypassing B4 NFQUEUE rules.

## Hold/reassembly/runtime-control dependency

- TCP reassembly and bounded hold/replay already fail open on timeout, pressure, lifecycle changes, and shutdown.
- Transactional runtime control now has readiness, canary, promote, abort, rollback, and last-good state.
- Neither subsystem currently consumes a functional capture-visibility mode. Without this addendum they can only rely on generic queue readiness/offload suspicion.

## Selected rule ownership and order

B4 will own only:

- `B4_PPE_PRE` in `mangle/PREROUTING`;
- `B4_PPE_FWD` in `mangle/FORWARD`;
- one provenance-tagged jump from each built-in chain;
- transient `B4_PPE_TEST_*` chains used by capability/self-test controllers.

The compiler will emit protocol/port/source-scope/`connskip` matches followed by the firmware `PPE` target. Rules are family-specific, deterministic, and do not save packet marks into conntrack state.

## NDM resilience choice

- Primary: an Entware/NDM netfilter hook installer that calls the B4 offload reconcile endpoint after mangle regeneration.
- Safety net: bounded periodic exact-state assertion integrated with the existing tables monitor lifecycle.
- Reconciliation restores one generation only and suppresses reapply storms.

## Capability decision

Router model and MediaTek strings are diagnostic metadata only. Support requires actual binaries/tables, exact `PPE` target registration, and a functional temporary `connskip` rule probe for each address family. Static support never implies visibility `PASS`.

## Main risks

1. Firmware-specific target semantics may differ across Keenetic releases.
2. Rule placement can look correct in `iptables-save` while incoming packets remain offloaded.
3. NDM regeneration can remove owned jumps after startup.
4. A dead controlled endpoint can mimic incomplete visibility.
5. Broad source scope can retain unrelated LAN handshakes on CPU.
6. Incorrect cleanup can remove third-party rules.
7. Automatic promotion must remain blocked until a controlled bidirectional A/B test proves visibility.

## Implementation gates

- PPE-1: capability model and read-only diagnostics.
- PPE-2: deterministic compiler and configuration model.
- PPE-3: transactional apply/remove/verify/rollback.
- PPE-4: NDM hook and bounded reconciliation.
- PPE-5: static/passive diagnostics, never functional PASS.
- PPE-6: isolated controlled bidirectional self-test.
- PPE-7: visibility-driven runtime safety gate.
- PPE-8: authenticated API, UI, issue bundle, migration, documentation.

Real Keenetic/MediaTek evidence remains an external acceptance gate and is not fabricated by workstation tests.
