# B4X FaultLab

Controlled Docker fixtures for L4/L7 synthetic validation. Router/phone
targets must use the Windows LAN IP plus these published ports — never a
container IP.

| Service | Port | Notes |
|---|---|---|
| HTTP | 18080 | `/health`, `/http/200`, `/http/redirect`, `/http/block-page`, `/http/delay`, `/http/error` |
| TCP | 18081 | echo / `FAULTLAB_TCP_MODE=delay-first|partial|fin|stall` |
| UDP | 18082 | echo with CorrelationID |
| TGB | 18083 | delayed first byte (default 5.1s / 64 bytes) |
| DNS | 18053 | A=198.51.100.10; `nx.*` NXDOMAIN; `fail.*` SERVFAIL |

```sh
docker compose -f tools/faultlab/docker-compose.yml up -d --build
python tools/faultlab/selftest.py
```

Firewall rules, if required, must be named `B4X-FaultLab-<CAMPAIGN_ID>` and
limited to the Private profile.
