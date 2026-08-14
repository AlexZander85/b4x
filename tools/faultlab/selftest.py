#!/usr/bin/env python3
"""FaultLab self-test. Missing response is FAIL, never PASS."""
from __future__ import annotations

import json
import os
import socket
import sys
import urllib.request

HOST = os.environ.get("FAULTLAB_HOST", "127.0.0.1")
HTTP = int(os.environ.get("FAULTLAB_HTTP_PORT", "18080"))
TCP = int(os.environ.get("FAULTLAB_TCP_PORT", "18081"))
UDP = int(os.environ.get("FAULTLAB_UDP_PORT", "18082"))
DNS = int(os.environ.get("FAULTLAB_DNS_PORT", "18053"))


def fail(msg: str) -> None:
    print("FAIL", msg)
    sys.exit(1)


def http_get(path: str) -> bytes:
    url = f"http://{HOST}:{HTTP}{path}"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read()


def main() -> int:
    body = json.loads(http_get("/health"))
    if not body.get("ok"):
        fail("health")
    if b"status" not in http_get("/http/200"):
        fail("http/200")
    s = socket.create_connection((HOST, TCP), timeout=5)
    s.sendall(b"ping")
    data = s.recv(256)
    s.close()
    if b"CORR=" not in data:
        fail(f"tcp echo {data!r}")
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(3)
    u.sendto(b"ping", (HOST, UDP))
    data, _ = u.recvfrom(256)
    u.close()
    if b"CORR=" not in data:
        fail(f"udp echo {data!r}")
    d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    d.settimeout(3)
    # tiny DNS query for example.test
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01"
    d.sendto(q, (HOST, DNS))
    ans, _ = d.recvfrom(512)
    d.close()
    if len(ans) < 12:
        fail("dns short")
    print("PASS faultlab self-test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
