---
sidebar_position: 5
title: RST Protection
---

Some DPI systems break connections by sending forged TCP RST packets pretending to be the server. The browser treats them as real and closes the connection.

This feature inspects incoming RST packets and drops the ones that look like injections.

## How it works

b4 applies three independent checks to every RST packet:

| Check | What it drops |
| --- | --- |
| **RST before server reply** | The RST arrived before any real reply from the server - a strong sign of an injection |
| **Repeated RST** | The second or later RST on the same connection - a legitimate connection very rarely sends more than one |
| **TTL mismatch** | The TTL of the RST packet differs significantly from the TTL of the first real server reply - the packet came from a different network hop |

:::info
Each check runs independently. A packet is dropped when **any one** of them triggers.
:::

## Settings

### Enable RST Protection

Turns protection on for this set.

### TTL Tolerance

Allowed TTL difference between the RST packet and the real server reply. Range: 1-20, default **3**.

:::tip
A value of 3 fits most networks. Raise it if b4 falsely drops legitimate RST packets (visible in the logs).
:::

## Logging

Every dropped RST is shown in the [logs](../../logs) with the trigger reason: TTL mismatch, RST before server reply, or repeated RST.
