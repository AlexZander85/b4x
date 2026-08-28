# Upstream issue draft (PENDING — not yet filed)

**Repo:** https://github.com/amnezia-vpn/amneziawg-go (module `github.com/amnezia-vpn/amneziawg-go/v3`)
**Pinned version:** `v3.1.20260814` (commit `1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1`)
**File:** `device/timers.go`, `Peer.NewTimer` callback
**Status:** draft — file as upstream issue when network/policy permits; reference
this file from `src/transport/wg/NOTICE.md` (Modifications section).

## Title

Data race on `Timer.duration` between the timer callback and `Timer.Del`

## Body

`device/timers.go` (`Peer.NewTimer`) resets `timer.duration` **after**
releasing `modifyingLock` inside the `time.AfterFunc` callback, while
`Timer.Del` (and `Timer.Mod`) write the same field **under**
`modifyingLock`. `runningLock` does not help: `Del` does not take it, so a
concurrent `Device.Down → Peer.Stop → timers stop` (`Del`/`DelSync`) races
with a callback that is already past `modifyingLock.Unlock()`.

Observed as a `-race` failure when the embedded device is torn down while
handshake/keepalive timers fire (WG tunnel session teardown under load).
Reproduces with `go test -race` on series runs; load-dependent.

Race window (upstream code, pinned commit):

```go
timer.modifyingLock.Lock()
if timer.duration == 0 {
        timer.modifyingLock.Unlock()
        return
}
duration := timer.duration
timer.modifyingLock.Unlock()
timer.duration = 0   // <-- unsynchronized write; races with Timer.Del
```

`Timer.Del` (same file):

```go
func (timer *Timer) Del() {
        timer.modifyingLock.Lock()
        timer.duration = 0
        timer.Stop()
        timer.modifyingLock.Unlock()
}
```

## Suggested minimal fix

Keep the reset under the already-held lock (semantics unchanged: zero
duration ⇒ do not fire; `expirationFunction` still runs unlocked):

```go
timer.modifyingLock.Lock()
if timer.duration == 0 {
        timer.modifyingLock.Unlock()
        return
}
duration := timer.duration
timer.duration = 0
timer.modifyingLock.Unlock()

expirationFunction(peer, duration)
```

## Local record

Fixed in our vendored copy (`src/vendor/...`) under the same patch;
`src/transport/wg/NOTICE.md` carries the Modifications entry and re-pinned
NOTICE hash.
