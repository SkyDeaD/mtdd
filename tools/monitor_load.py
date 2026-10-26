#!/usr/bin/env python3
"""Bounded, low-frequency process/host sampling; no IPs or credentials in output."""

import argparse
import json
import os
import re
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def process_sample(pid):
    base = Path("/proc") / str(pid)
    fields = (base / "stat").read_text().rsplit(")", 1)[1].split()
    status = {}
    for line in (base / "status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("VmRSS", "VmHWM", "Threads"):
            status[key] = int(value.split()[0])
    return {
        "pid": pid, "start_ticks": int(fields[19]),
        "cpu_ticks": int(fields[11]) + int(fields[12]),
        "rss_kib": status.get("VmRSS", 0), "peak_rss_kib": status.get("VmHWM", 0),
        "threads": status.get("Threads", 0), "fds": len(list((base / "fd").iterdir())),
    }


def tcp_pressure_sample(netstat, sockstat, page_size):
    result = {}
    names = {"ListenOverflows": "host_tcp_listen_overflows_total",
             "ListenDrops": "host_tcp_listen_drops_total",
             "SyncookiesSent": "host_tcp_syncookies_sent_total",
             "TCPMemoryPressures": "host_tcp_memory_pressure_total",
             "TCPBacklogDrop": "host_tcp_backlog_drops_total",
             "TCPSynRetrans": "host_tcp_syn_retransmits_total",
             "TCPTimeouts": "host_tcp_timeouts_total"}
    rows = netstat.splitlines()
    for header, values in zip(rows[::2], rows[1::2]):
        keys, numbers = header.split(), values.split()
        if keys and numbers and keys[0] == numbers[0] == "TcpExt:":
            for key, value in zip(keys[1:], numbers[1:]):
                if key in names:
                    result[names[key]] = int(value)
    for row in sockstat.splitlines():
        parts = row.split()
        if parts and parts[0] == "TCP:":
            values = dict(zip(parts[1::2], parts[2::2]))
            for key, output in [("inuse", "host_tcp_sockets_inuse"), ("tw", "host_tcp_time_wait")]:
                if key in values:
                    result[output] = int(values[key])
            if "mem" in values:
                result["host_tcp_memory_kib"] = int(values["mem"]) * page_size // 1024
    return result


def host_sample():
    values = [int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
    available = 0
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            available = int(line.split()[1])
    result = {"total": sum(values), "idle": values[3] + values[4], "steal": values[7],
              "available_kib": available}
    result.update(tcp_pressure_sample(Path("/proc/net/netstat").read_text(),
                                     Path("/proc/net/sockstat").read_text(),
                                     os.sysconf("SC_PAGESIZE")))
    return result


def fetch(url, token):
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=3) as response:
        body = response.read(8 * 1024 * 1024 + 1)
        if len(body) > 8 * 1024 * 1024:
            raise ValueError("monitor response limit")
        return body


def metrics_sample(text):
    result = {"payload_c2s_bytes": 0, "payload_s2c_bytes": 0, "rejected_total": 0,
              "me_connected_dcs": 0, "me_reconnects_total": 0,
              "backpressure_c2s_total": 0, "backpressure_s2c_total": 0}
    for outcome in ("success", "failure", "timeout", "replay"):
        result[f"handshake_{outcome}_total"] = 0
    exact = {"mtdd_connections_active": "connections_active",
             "mtdd_unique_ips_active": "unique_ips_active",
             "mtdd_connections_accepted_total": "accepted_total",
             "mtdd_replay_cache_entries": "replay_cache_entries",
             "mtdd_me_pending_buffer_bytes": "me_pending_buffer_bytes"}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        identity, value = line.rsplit(" ", 1)
        if identity in exact:
            result[exact[identity]] = int(value)
        elif identity.startswith("mtdd_connections_rejected_total{"):
            result["rejected_total"] += int(value)
        elif identity.startswith("mtdd_me_connected{"):
            result["me_connected_dcs"] += int(value)
        elif identity.startswith("mtdd_me_reconnects_total{"):
            result["me_reconnects_total"] += int(value)
        elif identity.startswith("mtdd_handshakes_total{"):
            match = re.search(r'result="(success|failure|timeout|replay)"', identity)
            if match:
                result[f"handshake_{match[1]}_total"] += int(value)
        elif identity.startswith("mtdd_backpressure_events_total{"):
            match = re.search(r'direction="(c2s|s2c)"', identity)
            if match:
                result[f"backpressure_{match[1]}_total"] += int(value)
        elif identity.startswith("mtdd_buffer_bytes{"):
            match = re.search(r'state="(queued|pending_write|relay)"', identity)
            if match:
                result[f"buffer_{match[1]}_bytes"] = int(value)
        elif identity.startswith("mtdd_user_payload_bytes_received_total{"):
            for direction in ("c2s", "s2c"):
                if f'direction="{direction}"' in identity:
                    result[f"payload_{direction}_bytes"] += int(value)
        elif identity.startswith("mtdd_unique_ips_estimate{"):
            match = re.search(r'period="(hour|day|week)"', identity)
            if match:
                result[f"unique_ips_{match[1]}_estimate"] = int(value)
    return result


def run(args):
    name, separator, token = Path(args.token_file).read_text().strip().partition("=")
    if not name or not separator or not token or "\n" in token:
        raise ValueError("invalid monitor token file")
    output = Path(args.output)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    previous_process = None
    previous_host = None
    deadline = time.monotonic() + args.seconds
    hz = os.sysconf("SC_CLK_TCK")
    with os.fdopen(fd, "w", buffering=1) as stream:
        while time.monotonic() < deadline:
            now = time.monotonic()
            sample = {"time_utc": datetime.now(timezone.utc).isoformat()}
            try:
                process = process_sample(args.pid)
                sample.update(process)
                if previous_process is not None:
                    before, old_process = previous_process
                    if process["start_ticks"] == old_process["start_ticks"]:
                        sample["cpu_percent_one_core"] = round(
                            100 * max(0, process["cpu_ticks"] - old_process["cpu_ticks"]) / hz / (now - before), 3)
                previous_process = (now, process)
            except (OSError, ValueError, IndexError) as error:
                sample["process_error"] = type(error).__name__
                previous_process = None
            try:
                host = host_sample()
                sample.update({key: value for key, value in host.items() if key.startswith("host_tcp_")})
                sample["host_available_kib"] = host["available_kib"]
                if previous_host is not None:
                    _, old_host = previous_host
                    ticks = host["total"] - old_host["total"]
                    if ticks > 0:
                        steal = host["steal"] - old_host["steal"]
                        idle = host["idle"] - old_host["idle"]
                        sample["host_busy_percent"] = round(100 * max(0, ticks - idle - steal) / ticks, 3)
                        sample["host_steal_percent"] = round(100 * max(0, steal) / ticks, 3)
                previous_host = (now, host)
            except (OSError, ValueError, IndexError) as error:
                sample["host_error"] = type(error).__name__
                previous_host = None
            try:
                sample.update(metrics_sample(fetch(args.api_url.rstrip("/") + "/metrics", token).decode()))
            except (OSError, ValueError, TimeoutError, UnicodeError) as error:
                sample["metrics_error"] = type(error).__name__
            stream.write(json.dumps(sample) + "\n")
            remaining = min(args.interval - (time.monotonic() - now), deadline - time.monotonic())
            if remaining > 0:
                time.sleep(remaining)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--api-url", default="http://127.0.0.1:19090")
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--seconds", type=float, default=3600)
    args = parser.parse_args()
    if args.pid < 1 or not 1 <= args.interval <= 60 or not 1 <= args.seconds <= 86400:
        parser.error("invalid PID, interval or sampling duration")
    run(args)
