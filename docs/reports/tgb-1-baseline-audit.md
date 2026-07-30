# TGB-1 — baseline audit and delayed-connection fixtures

The existing Telegram bridge path is `mtproto.TransparentBridge` behind the TPROXY listener. It reads the obfuscated prefix, resolves DC from original destination/handshake, then uses the bounded upstream ladder and fail-open worker path. Configuration is held by the atomic MTProto config snapshot and live status is projected through the existing handler.

The compatibility fixture records the historical five-second read deadline, zero-byte acceptance ambiguity, partial-prefix fail-open path, and delayed-first-byte corpus. The hardening stages below add typed dispositions and bounded state without changing the explicit proxy API or MTProto wire format.

Validation: existing `mtproto` and `tproxy` tests are preserved. TGB-2 replaces boolean ownership ambiguity with a structured outcome contract.

