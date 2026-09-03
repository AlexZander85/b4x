---
sidebar_position: 4
title: Keenetic
---

## Requirements

- Keenetic router with OPKG support
- Entware installed (required)

## Install Entware

### Newer models (with built-in storage)

1. Open the router web interface
2. Go to **System settings**
3. Enable the **OPKG package manager** component

### Older models (USB drive required)

1. Plug a USB drive into the router
2. Install Entware through the package manager

More details: [help.keenetic.com](https://help.keenetic.com/hc/en-us/articles/360021214160)

## Enable Netfilter components

Keenetic NDMS does not ship all the netfilter kernel modules b4 needs out of the box. Before installing b4, enable the required components:

1. In the router web interface, go to **System settings** → **Component options**
2. Enable **Netfilter** — the base netfilter component
3. Once Netfilter is enabled, a new option appears: enable **Xtables-addons for Netfilter** (provides `xt_connbytes` and other extensions b4 relies on)
4. Apply the changes and wait for the router to reboot or reload components

Then, over SSH, install the iptables userspace:

```bash
opkg install iptables
```

## Install b4

Connect over SSH and run:

```bash
curl -fsSL https://raw.githubusercontent.com/DanielLavrushin/b4/main/install.sh | sh
```

## Service control

```bash
/opt/etc/init.d/S99b4 start
/opt/etc/init.d/S99b4 stop
/opt/etc/init.d/S99b4 restart
```

## Paths

| What | Where |
| --- | --- |
| Binary | `/opt/sbin/b4` |
| Configuration | `/opt/etc/b4/b4.json` |
| Service | `/opt/etc/init.d/S99b4` |

## Architecture

- Older models (MT7621) - `mipsle_softfloat`
- Newer models (aarch64) - `arm64`

The installer detects the architecture automatically.

:::warning Without Entware
Without Entware, b4 is placed in `/tmp`, which is cleared on every reboot. For persistent operation, Entware is required.
:::

## Troubleshooting

After starting the service, check the log:

```bash
cat /var/log/b4/errors.log
```

If you see `xt_connbytes kernel module is not available`, the Netfilter components weren't enabled correctly — return to [Enable Netfilter components](#enable-netfilter-components) above and make sure both **Netfilter** and **Xtables-addons for Netfilter** are active.

If the log is empty (or has no errors), the b4 web interface should be reachable on the router's LAN IP.
