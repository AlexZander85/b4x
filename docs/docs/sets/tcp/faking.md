---
sidebar_position: 3
title: Faking
---

The Faking tab holds methods for sending fake packets and modifying real ones to deceive the DPI. Each section is a separate accordion in the interface.

See the [Payloads](../../settings/payloads) section for payload types and generation.

## Fake SNI packets

Sends packets with fake contents **before** the real ClientHello. The DPI analyzes the fake packet while the real data passes unnoticed. The fake packet does not reach the server thanks to the chosen strategy.

### Fake strategy

Picks **how** the fake packet becomes unprocessable to the server:

| Strategy | Mechanism |
| --- | --- |
| **TTL** | Reduced TTL - the packet expires on an intermediate hop and never reaches the server |
| **Random Sequence** | Random TCP sequence number - the server drops packets with an unexpected seq |
| **Past Sequence** | Past sequence number - the server has already processed that seq and ignores the repeat |
| **TCP Check** | Invalid TCP checksum - the server kernel drops the packet before processing |
| **MD5 Sum** | TCP MD5 option - a server without configured MD5 drops the packet |
| **TCP Timestamp** | Stale TCP timestamp - the server drops the packet because its timestamp is too far in the past |

### Payload type

The content of the fake packet. Full description of every type is in [Payloads](../../settings/payloads#payload-types).

| Type | Contents |
| --- | --- |
| Random | 1200 random bytes |
| Preset: Google | TLS ClientHello pretending to be Google |
| Preset: DuckDuckGo | TLS ClientHello pretending to be DuckDuckGo |
| Generated payload | Optimized ClientHello from [Settings -> Payloads](../../settings/payloads) |
| All zeros | 1200 zero bytes |
| Inverted original | Bitwise inversion of the real TLS packet |

:::tip Generated payloads
If no payload is available in the list, generate them first in [Settings -> Payloads](../../settings/payloads).
:::

### Parameters

| Parameter | Description | Range |
| --- | --- | --- |
| Fake TTL | TTL for fake packets. Must be enough to reach the DPI but expire before the server | 1-64 |
| Sequence offset | TCP sequence number shift (for pastseq/randseq strategies) | - |
| Timestamp decrement | Amount to subtract from the TCP timestamp (for the timestamp strategy, default 600000) | - |
| Fake packet count | How many fake packets to send before the real data | 1-20 |

:::tip Picking TTL
The right TTL depends on the number of network hops between you and the provider's DPI. Discovery picks TTL automatically. When tuning manually, start at `3` and adjust.
:::

### TLS modifications for fake packets

If the payload type contains a TLS structure (not Random and not all zeros), extra modifications for the fake ClientHello are available:

| Parameter | Description |
| --- | --- |
| Randomize TLS Random | Replaces the 32-byte Random field in the fake ClientHello with random bytes. Without it, the DPI may notice the Random field is identical in the fake and the real packet |
| Duplicate Session ID | Copies the Session ID from the real ClientHello into the fake one. The DPI may use Session ID to tie packets together |

---

## Fake SYN packets

Sends fake SYN packets during the TCP handshake - **before** the real connection begins. Confuses the DPI even before the connection is established.

:::warning
This is an aggressive technique - fake SYNs may affect some network equipment.
:::

| Parameter | Description | Range |
| --- | --- | --- |
| SYN MD5 Signature | Send a fake SYN with a TCP MD5 option before the real handshake | - |
| Payload length | Size of data in the fake SYN. `0` = header only, `>0` = attach a fake TLS payload | 0-1200 |
| TTL | TTL for fake SYN packets | 1-100 |

---

## TCP Desync

Desync injects fake TCP control packets (RST/FIN/ACK) with corrupted checksums and low TTL. These packets confuse stateful DPI but are dropped by the real server.

### Desync mode

| Mode | What it sends |
| --- | --- |
| **RST** | Fake RST packets with bad checksums - the DPI considers the connection torn down |
| **FIN** | Fake FIN packets with stale sequence numbers - the DPI considers the connection finished |
| **ACK** | Fake ACK packets with random future sequence/ack numbers - the DPI loses state |
| **Combo** | Sequence of RST + FIN + ACK |
| **Full** | Full attack: fake SYN, overlapping RST, PSH, and URG packets |

### Desync parameters

| Parameter | Description | Range |
| --- | --- | --- |
| Desync TTL | Low TTL ensures fake packets expire before the server | 1-50 |
| Packet count | Number of fake packets per desync attack | 1-20 |
| Post-ClientHello RST | Send a fake RST **after** the ClientHello to remove the connection from the DPI tracking table | - |

---

## Window manipulation

Sends fake ACK packets with altered TCP window sizes **before** the real packet. Fakes use low TTL - they expire before the server but confuse the DPI on intermediate hops.

| Mode | Description |
| --- | --- |
| **Zero window** | Fake packets: first window=0, then window=65535 |
| **Random** | 3-5 fake packets with random window sizes from the configured list |
| **Oscillation** | Cycles through custom window values |
| **Escalation** | Gradual increase: 0 -> 100 -> 500 -> 1460 -> 8192 -> 32768 -> 65535 |

In **Random** and **Oscillation** modes a custom list of window values (0-65535) can be specified. When the list is empty, defaults are used.

---

## Incoming response bypass

Manipulates the server's **incoming responses**. Used against DPI that throttles connections after a certain amount of data has been transferred (~15-20 KB). b4 injects fake packets toward the server that the DPI sees but that never reach the destination.

### Mode

| Mode | Description |
| --- | --- |
| **Fake packets** | Injects broken ACK packets toward the server with low TTL on every incoming data packet |
| **Reset injection** | Injects fake RST packets once the incoming byte threshold is reached |
| **FIN injection** | Injects fake FIN packets once the threshold is reached |
| **Desync Combo** | Injects an RST+FIN+ACK combo once the threshold is reached |

### Corruption strategy

How the fake packet becomes unprocessable:

| Strategy | Description |
| --- | --- |
| **Bad Checksum** | Corrupt the TCP checksum - packets get dropped by the kernel |
| **Bad Sequence** | Corrupt the sequence number - packets get ignored by the TCP stack |
| **Bad ACK** | Corrupt the ACK number - packets get ignored by the TCP stack |
| **Random** | Random method pick per packet |
| **All** | All corruptions at once: bad seq + bad ack + bad checksum |

### Incoming parameters

| Parameter | Description | Range |
| --- | --- | --- |
| Fake TTL | Low TTL ensures fakes expire before the server | 1-20 |
| Fake count | Number of fake packets per injection | 1-10 |
| Min threshold | Minimum amount of incoming data before triggering (KB) | 5-50 |
| Max threshold | Maximum threshold - randomized between min and max per connection | 5-50 |

:::info Thresholds and Fake mode
In **Fake packets** mode, thresholds are unused - fakes are sent on every incoming packet. Thresholds only apply to Reset, FIN, and Desync Combo modes.
:::

---

## ClientHello mutation

Modifies the structure of the **real** TLS ClientHello (not a fake). Randomizes the extension order and adds noise so the ClientHello does not match known DPI signatures.

:::warning Mutation changes the real packet
Unlike other sections on this tab, mutation modifies the **real** ClientHello that reaches the server. If a site stops working after mutation is turned on, disable it.
:::

### Mutation mode

| Mode | Description |
| --- | --- |
| **GREASE Extensions** | Insert GREASE extensions to deceive the DPI |
| **Padding** | Add a padding extension up to a target size |
| **Fake Extensions** | Insert fake/unknown TLS extensions |
| **Fake SNIs** | Add extra fake SNI entries |
| **Random** | Randomize extension order and add noise |
| **Advanced** | Combine several mutation techniques with manual tuning |

### Parameters by mode

**GREASE:**

| Parameter | Description | Range |
| --- | --- | --- |
| GREASE count | How many GREASE extensions to insert | 1-10 |

**Padding:**

| Parameter | Description | Range |
| --- | --- | --- |
| Padding size | Target ClientHello size with padding | 256-16384 bytes |

**Fake Extensions:**

| Parameter | Description | Range |
| --- | --- | --- |
| Fake Extensions count | How many fake TLS extensions to insert | 1-15 |

**Fake SNIs:**

Adds extra SNI values to the ClientHello. Enter domains (for example, `ya.ru`, `vk.com`) - they are injected into the SNI extension alongside the real domain.

**Advanced** exposes every parameter above for manual combination.
