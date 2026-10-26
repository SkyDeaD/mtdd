#!/usr/bin/env python3
"""Opt-in real Telegram ME/FakeTLS + native management smoke test.

Run only on an explicitly authorized host with native/public source addressing.
Starts a temporary mtdd instance; never modifies an existing config/users file.
"""

import argparse
import importlib.util
import json
import os
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(binary, supplied_config):
    probe_path = Path(__file__).resolve().parents[2] / "tools" / "faketls_probe.py"
    spec = importlib.util.spec_from_file_location("faketls_probe", probe_path)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    with tempfile.TemporaryDirectory(prefix="mtdd-live-") as directory:
        root = Path(directory)
        config = json.loads(supplied_config.read_text())
        proxy_port, api_port = unused_port(), unused_port()
        config.update(proxy_host="127.0.0.1", proxy_port=proxy_port,
                      control_host="127.0.0.1", control_port=api_port,
                      users_path=str(root / "users.json"), shutdown_timeout_seconds=2,
                      api_token_env="MTDD_API_TOKEN")
        config.pop("me_config_path", None)
        config.pop("me_secret_path", None)
        path = root / "config.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        token = secrets.token_hex(32)

        def request(route, method="GET", body=None):
            headers = {"Authorization": f"Bearer {token}"}
            payload = None if body is None else json.dumps(body).encode()
            if payload is not None:
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(f"http://127.0.0.1:{api_port}" + route,
                                         payload, headers, method=method)
            try:
                response = urllib.request.urlopen(req, timeout=4)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, response.read()

        def mutate(route, method, body=None):
            status, payload = request(route, method, body)
            if status not in (200, 201):
                raise AssertionError(f"mutation {method} {route}: status {status}, runtime not acknowledged")
            return json.loads(payload)["data"]

        def probe(key, pq=False, on_reply=None):
            return client.probe("127.0.0.1", proxy_port, config["tls_domain"],
                                bytes.fromhex(key), pq=pq, timeout=15, on_reply=on_reply)

        def must_reject(key):
            try:
                probe(key)
            except (OSError, RuntimeError):
                return
            raise AssertionError("revoked/disabled secret still completed a handshake")

        def closes_after_mutation(stream, action):
            action()
            stream.settimeout(3)
            if stream.recv(1) != b"":
                raise AssertionError("revoked session was not closed")

        with (root / "process.log").open("wb") as log:
            child = subprocess.Popen([str(binary), "--config", str(path)],
                                     env={**os.environ, "MTDD_API_TOKEN": token},
                                     stdout=log, stderr=subprocess.STDOUT)
            keys = []
            try:
                deadline = time.monotonic() + 10
                while True:
                    if child.poll() is not None:
                        raise AssertionError("mtdd exited during initialization")
                    try:
                        if request("/v1/health")[0] == 200:
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    if time.monotonic() > deadline:
                        raise AssertionError("management startup timeout")
                    time.sleep(0.02)
                created = mutate("/v1/users", "POST", {"name": "live_probe", "max_connections": 4})
                keys.append(created["secret"])
                deadline = time.monotonic() + 40
                while request("/v1/ready")[0] != 200:
                    if child.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError("ME readiness startup timeout")
                    time.sleep(0.1)
                print("classical:", json.dumps(probe(keys[-1])))
                print("PQ:", json.dumps(probe(keys[-1], pq=True)))
                if request("/v1/ready")[0] != 200:
                    raise AssertionError("usable ME and enabled user did not make runtime ready")
                probe(keys[-1], on_reply=lambda stream: closes_after_mutation(
                    stream, lambda: mutate("/v1/users/live_probe", "PATCH", {"enabled": False})))
                must_reject(keys[-1])
                mutate("/v1/users/live_probe", "PATCH", {"enabled": True})

                def rotate(stream):
                    def action():
                        keys.append(mutate("/v1/users/live_probe/rotate-secret", "POST", {})["secret"])
                    closes_after_mutation(stream, action)

                probe(keys[-1], on_reply=rotate)
                must_reject(keys[0])
                print("rotated secret:", json.dumps(probe(keys[-1])))
                status, metrics = request("/metrics")
                assert status == 200 and b"mtdd_user_payload_bytes_received_total" in metrics
                assert token.encode() not in metrics and all(key.encode() not in metrics for key in keys)
                probe(keys[-1], on_reply=lambda stream: closes_after_mutation(
                    stream, lambda: mutate("/v1/users/live_probe", "DELETE")))
                must_reject(keys[-1])
                process_status = Path(f"/proc/{child.pid}/status").read_text()
                for line in process_status.splitlines():
                    if line.startswith(("VmRSS:", "VmHWM:")):
                        print("smoke resource observation:", line.strip())
                print("live smoke: passed; ME, classical/PQ FakeTLS, native API, disable/rotate/delete invalidation")
            except Exception:
                # Counters only: never emit arbitrary logs, API bodies or credentials.
                try:
                    _, metrics = request("/metrics")
                    prefixes = ("mtdd_handshake", "mtdd_connections", "mtdd_me_", "mtdd_rejected", "mtdd_backpressure")
                    for line in metrics.decode().splitlines():
                        if line.startswith(prefixes):
                            print("diagnostic:", line)
                except (OSError, urllib.error.URLError):
                    pass
                raise
            finally:
                if child.poll() is None:
                    child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
                    raise AssertionError("bounded shutdown failed")
                logs = (root / "process.log").read_bytes()
                assert token.encode() not in logs and all(key.encode() not in logs for key in keys), "credentials leaked to process log"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(), args.config.resolve())
