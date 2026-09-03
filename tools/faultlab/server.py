#!/usr/bin/env python3
"""B4X FaultLab: controlled DNS/TCP/HTTP/TLS/UDP/TGB fixtures.

Every response carries a CorrelationID. Endpoints are for L4/L7 synthetic
tests only — they never impersonate production YouTube/Telegram.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import socketserver
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def new_corr() -> str:
    return str(uuid.uuid4())


class HTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _send(self, code: int, body: bytes, extra: dict | None = None):
        corr = self.headers.get("X-Correlation-ID") or new_corr()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Correlation-ID", corr)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/health", "/"):
            body = json.dumps({"ok": True, "service": "faultlab", "corr": new_corr()}).encode()
            self._send(200, body)
            return
        if path == "/http/200":
            self._send(200, json.dumps({"status": 200, "corr": new_corr()}).encode())
            return
        if path == "/http/redirect":
            body = b'{"status":"redirect"}'
            self._send(302, body, {"Location": "/http/200"})
            return
        if path == "/http/block-page":
            self._send(200, b"<html><title>controlled-block</title></html>")
            return
        if path == "/http/delay":
            time.sleep(float(os.environ.get("FAULTLAB_HTTP_DELAY", "1.5")))
            self._send(200, json.dumps({"delayed": True, "corr": new_corr()}).encode())
            return
        if path == "/http/error":
            self._send(503, json.dumps({"error": "controlled-origin", "corr": new_corr()}).encode())
            return
        self._send(404, json.dumps({"error": "unknown fixture", "path": path}).encode())


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        mode = os.environ.get("FAULTLAB_TCP_MODE", "echo")
        corr = new_corr().encode()
        try:
            if mode == "delay-first":
                time.sleep(float(os.environ.get("FAULTLAB_TCP_DELAY", "5.1")))
                self.request.sendall(b"CORR=" + corr + b"\n")
            elif mode == "partial":
                self.request.sendall(b"COR")
                time.sleep(0.2)
            elif mode == "fin":
                self.request.shutdown(socket.SHUT_RDWR)
            elif mode == "stall":
                time.sleep(30)
            else:
                data = self.request.recv(4096)
                self.request.sendall(b"CORR=" + corr + b" ECHO=" + data)
        except OSError:
            return


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        sock = self.request[1]
        corr = new_corr().encode()
        sock.sendto(b"CORR=" + corr + b" ECHO=" + data, self.client_address)


class TGBHandler(socketserver.BaseRequestHandler):
    """Delayed-first-byte fixture for ISSUE_277 / FT-AA."""

    def handle(self):
        delay = float(os.environ.get("FAULTLAB_TGB_DELAY", "5.1"))
        nbytes = int(os.environ.get("FAULTLAB_TGB_BYTES", "64"))
        time.sleep(delay)
        payload = bytes([0xEF]) + hashlib.sha256(new_corr().encode()).digest()
        payload = (payload * ((nbytes // len(payload)) + 1))[:nbytes]
        try:
            self.request.sendall(payload)
            time.sleep(0.2)
        except OSError:
            return


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_dns(port: int):
    """Minimal DNS: A=198.51.100.10, NXDOMAIN for nx., SERVFAIL for fail."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))

    def loop():
        while True:
            try:
                data, addr = sock.recvfrom(512)
            except OSError:
                return
            if len(data) < 12:
                continue
            qname = _qname(data[12:])
            tid = data[:2]
            flags = b"\x81\x80"
            rcode = 0
            answers = b""
            if qname.startswith("nx."):
                rcode = 3
            elif qname.startswith("fail."):
                rcode = 2
            else:
                answers = _a_record(qname, b"\xc6\x33\x64\x0a")  # 198.51.100.10
            hdr = tid + bytes([0x81, 0x80 | rcode]) + data[4:6] + (
                b"\x00\x01" if answers else b"\x00\x00"
            ) + b"\x00\x00\x00\x00"
            # rebuild with original question
            qend = 12 + _question_len(data[12:])
            msg = hdr + data[12:qend] + answers
            if rcode != 0:
                msg = tid + bytes([0x81, 0x80 | rcode]) + data[4:6] + b"\x00\x00\x00\x00\x00\x00" + data[12:qend]
            sock.sendto(msg, addr)

    threading.Thread(target=loop, daemon=True).start()


def _qname(buf: bytes) -> str:
    labels = []
    i = 0
    while i < len(buf) and buf[i] != 0:
        n = buf[i]
        labels.append(buf[i + 1 : i + 1 + n].decode("ascii", "ignore"))
        i += 1 + n
    return ".".join(labels).lower()


def _question_len(buf: bytes) -> int:
    i = 0
    while i < len(buf) and buf[i] != 0:
        i += 1 + buf[i]
    return i + 1 + 4


def _a_record(qname: str, ip: bytes) -> bytes:
    return b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" + ip


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--http-port", type=int, default=int(os.environ.get("FAULTLAB_HTTP_PORT", "18080")))
    p.add_argument("--tcp-port", type=int, default=int(os.environ.get("FAULTLAB_TCP_PORT", "18081")))
    p.add_argument("--udp-port", type=int, default=int(os.environ.get("FAULTLAB_UDP_PORT", "18082")))
    p.add_argument("--tgb-port", type=int, default=int(os.environ.get("FAULTLAB_TGB_PORT", "18083")))
    p.add_argument("--dns-port", type=int, default=int(os.environ.get("FAULTLAB_DNS_PORT", "18053")))
    args = p.parse_args()

    serve_dns(args.dns_port)
    httpd = ThreadingHTTPServer(("0.0.0.0", args.http_port), HTTPHandler)
    tcp = ThreadedTCP(("0.0.0.0", args.tcp_port), TCPHandler)
    udp = ThreadedUDP(("0.0.0.0", args.udp_port), UDPHandler)
    tgb = ThreadedTCP(("0.0.0.0", args.tgb_port), TGBHandler)
    for srv in (httpd, tcp, udp, tgb):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(
        json.dumps(
            {
                "faultlab": "ready",
                "http": args.http_port,
                "tcp": args.tcp_port,
                "udp": args.udp_port,
                "tgb": args.tgb_port,
                "dns": args.dns_port,
            }
        ),
        flush=True,
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
