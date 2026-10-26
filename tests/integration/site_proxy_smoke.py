#!/usr/bin/env python3
"""Verify trusted HTTPS and authenticated FakeTLS on one address/port."""

import argparse
import http.client
import importlib.util
import json
import os
import socket
import ssl
from pathlib import Path


def run(host, port, domain, secret):
    with socket.create_connection((host, port), timeout=15) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=domain) as tls:
            tls.sendall(
                f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode("ascii")
            )
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read(4096)
            assert response.status == 200, f"HTTPS returned {response.status}"
            assert b"Service is online" in body, "unexpected placeholder"
            print("Trusted HTTPS placeholder:", response.status, tls.version())
    path = Path(__file__).resolve().parents[2] / "tools" / "faketls_probe.py"
    spec = importlib.util.spec_from_file_location("faketls_probe", path)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    for pq in (False, True):
        print("FakeTLS/ME:", json.dumps(client.probe(host, port, domain, secret, pq=pq, timeout=20)))
    print("Same-port HTTPS + FakeTLS acceptance passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("domain")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args()
    key = bytes.fromhex(os.environ["MTDD_PROXY_SECRET"])
    if len(key) != 16:
        raise SystemExit("MTDD_PROXY_SECRET must contain 32 hex characters")
    run(args.host, args.port, args.domain, key)
