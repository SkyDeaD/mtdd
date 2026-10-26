#!/usr/bin/env python3
"""Exercise the download path without root, systemd, or external network."""

import hashlib
import http.server
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.branch = self.root / "channel-dev"
        self.branch.mkdir()
        self.binary = b"#!/bin/sh\necho mtdd-test\n"
        (self.branch / "mtdd-linux-x86_64").write_bytes(self.binary)
        self.checksum(hashlib.sha256(self.binary).hexdigest())
        handler = lambda *args, **kwargs: QuietHandler(  # noqa: E731
            *args, directory=str(self.root), **kwargs
        )
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def checksum(self, digest):
        (self.branch / "SHA256SUMS").write_text(f"{digest}  mtdd-linux-x86_64\n")

    def run_installer(self, *args):
        return subprocess.run(
            ["bash", str(INSTALLER), "--binary-only",
             "--repo", "example/mtdd", "--branch", "dev", "--base-url",
             f"http://127.0.0.1:{self.server.server_port}", "--output",
             str(self.root / "installed"), *args],
            text=True, capture_output=True, timeout=20,
        )

    def test_installs_selected_branch_and_checks_hash(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "installed").read_bytes(), self.binary)
        self.assertTrue((self.root / "installed").stat().st_mode & 0o111)
        self.assertIn("mtdd", result.stdout)
        self.assertIn("dev", result.stdout)
        self.assertIn("SHA-256", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_bad_checksum_preserves_existing_binary(self):
        (self.root / "installed").write_bytes(b"previous")
        self.checksum("0" * 64)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "installed").read_bytes(), b"previous")

    def test_invalid_branch_is_rejected(self):
        result = self.run_installer("--branch", "other")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "installed").exists())

    def test_help_describes_interactive_and_automation_options(self):
        result = subprocess.run(["bash", str(INSTALLER), "--help"],
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        for option in ("--branch", "--domain", "--ad-tag", "--public-host",
                       "--public-port", "--binary-only"):
            self.assertIn(option, result.stdout)

    def test_help_describes_management_commands(self):
        result = subprocess.run(["bash", str(INSTALLER), "--help"],
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        for token in ("status", "users add", "users remove", "users rotate",
                      "metrics", "uninstall", "menu", "mtdd-ctl", "logs",
                      "check-config", "host"):
            self.assertIn(token, result.stdout)

    def test_unknown_command_is_rejected(self):
        result = subprocess.run(["bash", str(INSTALLER), "bogus"],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Неизвестная команда", result.stderr)

    def test_management_commands_are_incompatible_with_binary_only(self):
        result = subprocess.run(["bash", str(INSTALLER), "status", "--binary-only"],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--binary-only", result.stderr)

    def test_management_commands_fail_cleanly_without_installation(self):
        for command in (["status"], ["users", "list"], ["menu"], ["check-config"]):
            result = subprocess.run(["bash", str(INSTALLER), *command],
                                    text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0, command)
            self.assertRegex(result.stderr + result.stdout, "root|установ")

    def test_terminal_colors_respect_no_color(self):
        if not shutil.which("script"):
            self.skipTest("script is required for a pseudo-terminal")
        args = ["bash", str(INSTALLER), "--binary-only",
                "--branch", "dev", "--base-url", f"http://127.0.0.1:{self.server.server_port}",
                "--output", str(self.root / "installed")]
        env = os.environ.copy()
        env["TERM"] = "xterm"
        env.pop("NO_COLOR", None)
        for disabled in (False, True):
            if disabled:
                env["NO_COLOR"] = "1"
            result = subprocess.run(["script", "-q", "-e", "-c", shlex.join(args), "/dev/null"],
                                    env=env, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual("\x1b[" in result.stdout, not disabled)

    def test_interactive_install_accepts_answers_through_a_pipe(self):
        binary_path = os.environ.get("MTDD_INSTALLER_INTEGRATION_BINARY")
        if not binary_path or not shutil.which("unshare") or not shutil.which("script"):
            self.skipTest("integration binary, unshare and script are required")
        if subprocess.run(["unshare", "-Ur", "-m", "true"], capture_output=True).returncode:
            self.skipTest("unprivileged mount namespaces unavailable")
        binary = pathlib.Path(binary_path).resolve().read_bytes()
        (self.branch / "mtdd-linux-x86_64").write_bytes(binary)
        self.checksum(hashlib.sha256(binary).hexdigest())
        sandbox = self.root / "interactive"
        for name in ("etc", "varlib", "bin", "run/systemd/system", "commands"):
            (sandbox / name).mkdir(parents=True)
        (sandbox / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\nmtdd:x:0:0:mtdd:/var/lib/mtdd:/usr/sbin/nologin\n")
        (sandbox / "etc/group").write_text("root:x:0:\nmtdd:x:0:\n")
        for name, content in {
            "systemctl": "#!/bin/sh\nexit 0\n",
            "curl": "#!/bin/sh\ncase \"$*\" in *api.ipify.org*) printf '8.8.8.8';; *) exec /usr/bin/curl \"$@\";; esac\n",
        }.items():
            command = sandbox / "commands" / name
            command.write_text(content)
            command.chmod(0o755)
        env = os.environ.copy()
        env.update(MTDD_TEST_SANDBOX=str(sandbox), MTDD_TEST_INSTALLER=str(INSTALLER),
                   MTDD_TEST_URL=f"http://127.0.0.1:{self.server.server_port}",
                   PATH=f"{sandbox / 'commands'}:/usr/bin:/bin", TERM="dumb")
        command = r'''
set -eu
mount --bind "$MTDD_TEST_SANDBOX/etc" /etc
mount --bind "$MTDD_TEST_SANDBOX/varlib" /var/lib
mount --bind "$MTDD_TEST_SANDBOX/bin" /usr/local/bin
mount --bind "$MTDD_TEST_SANDBOX/run" /run
script -q -e -c 'bash "$MTDD_TEST_INSTALLER" --branch dev --base-url "$MTDD_TEST_URL" --domain bob.example.org --ad-tag 00112233445566778899aabbccddeeff --port 14443 --user bob --public-host proxy.example.org --public-port 443' /dev/null
python3 -c 'from pathlib import Path; [Path(p).unlink() for p in ("/etc/mtdd/config.json", "/etc/mtdd/credentials.env", "/var/lib/mtdd/users.json")]'
printf 'dev\nexample.org\n00112233445566778899aabbccddeeff\n14443\nalice\n' |
  script -q -e -c 'bash "$MTDD_TEST_INSTALLER" --base-url "$MTDD_TEST_URL" --public-port 443' /dev/null
'''
        result = subprocess.run(["unshare", "-Ur", "-m", "bash", "-c", command],
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = json.loads((sandbox / "etc/mtdd/config.json").read_text())
        self.assertEqual(config["proxy_port"], 14443)
        self.assertEqual(config["public_host"], "8.8.8.8")
        self.assertIn("alice: https://t.me/proxy?", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_system_install_and_update_in_isolated_mount_namespace(self):
        binary_path = os.environ.get("MTDD_INSTALLER_INTEGRATION_BINARY")
        if not binary_path or not shutil.which("unshare"):
            self.skipTest("set MTDD_INSTALLER_INTEGRATION_BINARY and install unshare")
        probe = subprocess.run(["unshare", "-Ur", "-m", "true"], capture_output=True)
        if probe.returncode:
            self.skipTest("unprivileged mount namespaces unavailable")
        binary = pathlib.Path(binary_path).resolve().read_bytes()
        (self.branch / "mtdd-linux-x86_64").write_bytes(binary)
        self.checksum(hashlib.sha256(binary).hexdigest())
        sandbox = self.root / "sandbox"
        for name in ("etc", "varlib", "bin", "run/systemd/system", "commands"):
            (sandbox / name).mkdir(parents=True)
        (sandbox / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\nmtdd:x:0:0:mtdd:/var/lib/mtdd:/usr/sbin/nologin\n"
        )
        (sandbox / "etc/group").write_text("root:x:0:\nmtdd:x:0:\n")
        systemctl = sandbox / "commands/systemctl"
        systemctl.write_text("#!/bin/sh\nexit 0\n")
        systemctl.chmod(0o755)
        curl = sandbox / "commands/curl"
        curl.write_text("#!/bin/sh\ncase \"$*\" in *api.ipify.org*) printf '8.8.8.8';; *) exec /usr/bin/curl \"$@\";; esac\n")
        curl.chmod(0o755)
        env = os.environ.copy()
        env["MTDD_TEST_SANDBOX"] = str(sandbox)
        env["MTDD_TEST_INSTALLER"] = str(INSTALLER)
        env["MTDD_TEST_URL"] = f"http://127.0.0.1:{self.server.server_port}"
        env["PATH"] = f"{sandbox / 'commands'}:/usr/bin:/bin"
        script = r'''
set -eu
mount --bind "$MTDD_TEST_SANDBOX/etc" /etc
mount --bind "$MTDD_TEST_SANDBOX/varlib" /var/lib
mount --bind "$MTDD_TEST_SANDBOX/bin" /usr/local/bin
mount --bind "$MTDD_TEST_SANDBOX/run" /run
bash "$MTDD_TEST_INSTALLER" --repo example/mtdd --branch dev \
  --base-url "$MTDD_TEST_URL" --domain example.org \
  --ad-tag 00112233445566778899aabbccddeeff --port 14443 --user alice \
  --public-host proxy.example.org --public-port 443
bash "$MTDD_TEST_INSTALLER" --repo example/mtdd --branch dev \
  --base-url "$MTDD_TEST_URL" --domain ignored.example --port 14444
python3 -c 'import json; p="/etc/mtdd/config.json"; d=json.load(open(p)); del d["public_host"]; open(p,"w").write(json.dumps(d))'
bash "$MTDD_TEST_INSTALLER" --repo example/mtdd --branch dev \
  --base-url "$MTDD_TEST_URL"
'''
        result = subprocess.run(["unshare", "-Ur", "-m", "bash", "-c", script],
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = json.loads((sandbox / "etc/mtdd/config.json").read_text())
        users = json.loads((sandbox / "varlib/mtdd/users.json").read_text())
        self.assertEqual(config["proxy_port"], 14443)
        self.assertEqual(config["tls_domain"], "example.org")
        self.assertEqual(config["public_host"], "8.8.8.8")
        self.assertEqual(config["public_port"], 443)
        self.assertEqual(users["users"][0]["name"], "alice")
        self.assertEqual(len(users["users"][0]["secret"]), 32)
        link = ("https://t.me/proxy?server=proxy.example.org&port=443&secret=ee"
                + users["users"][0]["secret"] + "example.org".encode().hex())
        self.assertEqual(result.stdout.count(link), 2)
        self.assertIn(link.replace("proxy.example.org", "8.8.8.8"), result.stdout)
        self.assertIn("Telegram", result.stdout)
        self.assertIn("systemctl status mtdd", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)
        self.assertEqual((sandbox / "etc/mtdd/credentials.env").stat().st_mode & 0o777, 0o600)
        self.assertTrue((sandbox / "etc/systemd/system/mtdd.service").exists())
        bad_candidate = b"#!/bin/sh\nexit 1\n"
        (self.branch / "mtdd-linux-x86_64").write_bytes(bad_candidate)
        self.checksum(hashlib.sha256(bad_candidate).hexdigest())
        failed = subprocess.run(["unshare", "-Ur", "-m", "bash", "-c", script],
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual((sandbox / "bin/mtdd").read_bytes(), binary)

    def test_management_subcommands_in_isolated_mount_namespace(self):
        binary_path = os.environ.get("MTDD_INSTALLER_INTEGRATION_BINARY")
        if not binary_path or not shutil.which("unshare") or not shutil.which("script"):
            self.skipTest("integration binary, unshare and script are required")
        if subprocess.run(["unshare", "-Ur", "-m", "true"], capture_output=True).returncode:
            self.skipTest("unprivileged mount namespaces unavailable")
        binary = pathlib.Path(binary_path).resolve().read_bytes()
        (self.branch / "mtdd-linux-x86_64").write_bytes(binary)
        self.checksum(hashlib.sha256(binary).hexdigest())
        sandbox = self.root / "manage"
        for name in ("etc", "varlib", "bin", "run/systemd/system", "commands"):
            (sandbox / name).mkdir(parents=True)
        (sandbox / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\nmtdd:x:0:0:mtdd:/var/lib/mtdd:/usr/sbin/nologin\n")
        (sandbox / "etc/group").write_text("root:x:0:\nmtdd:x:0:\n")
        for name, content in {
            "systemctl": "#!/bin/sh\nexit 0\n",
            "curl": "#!/bin/sh\ncase \"$*\" in *api.ipify.org*) printf '8.8.8.8';; *) exec /usr/bin/curl \"$@\";; esac\n",
        }.items():
            command = sandbox / "commands" / name
            command.write_text(content)
            command.chmod(0o755)
        env = os.environ.copy()
        env.update(MTDD_TEST_SANDBOX=str(sandbox), MTDD_TEST_INSTALLER=str(INSTALLER),
                   MTDD_TEST_URL=f"http://127.0.0.1:{self.server.server_port}",
                   PATH=f"{sandbox / 'commands'}:/usr/bin:/bin", TERM="dumb")
        script = r'''
set -eu
mount --bind "$MTDD_TEST_SANDBOX/etc" /etc
mount --bind "$MTDD_TEST_SANDBOX/varlib" /var/lib
mount --bind "$MTDD_TEST_SANDBOX/bin" /usr/local/bin
mount --bind "$MTDD_TEST_SANDBOX/run" /run
bash "$MTDD_TEST_INSTALLER" --repo example/mtdd --branch dev \
  --base-url "$MTDD_TEST_URL" --domain example.org \
  --ad-tag 00112233445566778899aabbccddeeff --port 14443 --user alice \
  --public-host proxy.example.org --public-port 443 >/dev/null
test -x /usr/local/bin/mtdd-ctl
bash "$MTDD_TEST_INSTALLER" check-config
if bash "$MTDD_TEST_INSTALLER" status >"$MTDD_TEST_SANDBOX/status.out" 2>&1; then
  echo "status must fail while the API is down" >&2
  exit 1
fi
grep -q "не отвечает" "$MTDD_TEST_SANDBOX/status.out"
if bash "$MTDD_TEST_INSTALLER" users list >"$MTDD_TEST_SANDBOX/users.out" 2>&1; then
  echo "users list must fail while the API is down" >&2
  exit 1
fi
printf '0\n' | script -q -e -c 'bash "$MTDD_TEST_INSTALLER" menu' /dev/null
'''
        result = subprocess.run(["unshare", "-Ur", "-m", "bash", "-c", script],
                                env=env, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Конфигурация корректна", result.stdout)
        self.assertIn("управление прокси", result.stdout)
        self.assertIn("Готово", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)


if __name__ == "__main__":
    unittest.main()
