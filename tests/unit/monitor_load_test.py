"""Monitor output remains aggregate-only and private."""

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "monitor_load", Path(__file__).resolve().parents[2] / "tools" / "monitor_load.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MonitorTest(unittest.TestCase):
    def test_metrics_are_aggregate_only(self):
        sample = MODULE.metrics_sample('''# comment
mtdd_connections_active 6
mtdd_unique_ips_active 1
mtdd_user_payload_bytes_received_total{user="a",direction="c2s"} 10
mtdd_user_payload_bytes_received_total{user="b",direction="c2s"} 20
mtdd_user_payload_bytes_received_total{user="a",direction="s2c"} 40
mtdd_unique_ips_estimate{period="week"} 99
mtdd_connections_rejected_total{reason="overload"} 3
mtdd_connections_rejected_total{reason="auth_failed"} 2
mtdd_handshakes_total{result="failure"} 4
mtdd_replay_cache_entries 17
mtdd_backpressure_events_total{direction="c2s"} 8
mtdd_buffer_bytes{state="relay"} 1024
mtdd_me_connected{dc="2"} 1
mtdd_me_reconnects_total{dc="2"} 7
unrelated_metric{ip="192.0.2.7",secret="private"} 1
''')
        self.assertEqual(sample["connections_active"], 6)
        self.assertEqual(sample["unique_ips_active"], 1)
        self.assertEqual(sample["payload_c2s_bytes"], 30)
        self.assertEqual(sample["payload_s2c_bytes"], 40)
        self.assertEqual(sample["unique_ips_week_estimate"], 99)
        self.assertEqual(sample["rejected_total"], 5)
        self.assertEqual(sample["handshake_failure_total"], 4)
        self.assertEqual(sample["replay_cache_entries"], 17)
        self.assertEqual(sample["backpressure_c2s_total"], 8)
        self.assertEqual(sample["buffer_relay_bytes"], 1024)
        self.assertEqual(sample["me_connected_dcs"], 1)
        self.assertEqual(sample["me_reconnects_total"], 7)
        self.assertNotIn("192.0.2.7", json.dumps(sample))
        self.assertNotIn("private", json.dumps(sample))

    def test_kernel_pressure_is_host_wide_and_memory_is_pages(self):
        result = MODULE.tcp_pressure_sample(
            "TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPMemoryPressures\n"
            "TcpExt: 2 3 4 5\n",
            "TCP: inuse 7 orphan 0 tw 11 alloc 9 mem 13\n", 4096)
        self.assertEqual(result["host_tcp_listen_overflows_total"], 3)
        self.assertEqual(result["host_tcp_listen_drops_total"], 4)
        self.assertEqual(result["host_tcp_memory_pressure_total"], 5)
        self.assertEqual(result["host_tcp_syncookies_sent_total"], 2)
        self.assertEqual(result["host_tcp_memory_kib"], 52)
        self.assertEqual(result["host_tcp_sockets_inuse"], 7)
        self.assertEqual(result["host_tcp_time_wait"], 11)

    def test_private_output_and_token_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "test-token-must-never-appear"
            (root / "token").write_text("MTDD_API_TOKEN=" + token + "\n")
            args = SimpleNamespace(pid=os.getpid(), token_file=root / "token",
                                   output=root / "samples.jsonl", seconds=0.02,
                                   interval=1, api_url="http://127.0.0.1:19090")
            with patch.object(MODULE, "fetch", return_value=b"mtdd_unique_ips_active 1\n"):
                MODULE.run(args)
            data = args.output.read_text()
            self.assertNotIn(token, data)
            self.assertEqual(stat.S_IMODE(args.output.stat().st_mode), 0o600)
            sample = json.loads(data.splitlines()[0])
            self.assertEqual(sample["unique_ips_active"], 1)
            self.assertGreater(sample["rss_kib"], 0)
            with self.assertRaises(FileExistsError):
                MODULE.run(args)

    def test_stale_pid_does_not_hide_host_or_api_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "token").write_text("MTDD_API_TOKEN=test-token\n")
            args = SimpleNamespace(pid=123, token_file=root / "token", output=root / "samples",
                                   seconds=0.02, interval=1, api_url="http://127.0.0.1:19090")
            with patch.object(MODULE, "process_sample", side_effect=FileNotFoundError):
                with patch.object(MODULE, "fetch", return_value=b"mtdd_connections_active 7\n"):
                    MODULE.run(args)
            sample = json.loads(args.output.read_text().splitlines()[0])
            self.assertEqual(sample["process_error"], "FileNotFoundError")
            self.assertEqual(sample["connections_active"], 7)
            self.assertGreater(sample["host_available_kib"], 0)

    def test_api_error_preserves_process_and_host_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "token").write_text("MTDD_API_TOKEN=test-token\n")
            args = SimpleNamespace(pid=os.getpid(), token_file=root / "token", output=root / "samples",
                                   seconds=0.02, interval=1, api_url="http://127.0.0.1:19090")
            with patch.object(MODULE, "fetch", side_effect=OSError):
                MODULE.run(args)
            sample = json.loads(args.output.read_text().splitlines()[0])
            self.assertEqual(sample["metrics_error"], "OSError")
            self.assertGreater(sample["rss_kib"], 0)
            self.assertGreater(sample["host_available_kib"], 0)

    def test_malformed_token_file_has_explicit_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "token").write_text("malformed-with-no-equals")
            args = SimpleNamespace(token_file=root / "token")
            with self.assertRaisesRegex(ValueError, "invalid monitor token file"):
                MODULE.run(args)


if __name__ == "__main__":
    unittest.main()
