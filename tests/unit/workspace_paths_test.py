"""CI and tests must not depend on a developer-specific temporary directory."""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class WorkspacePathsTest(unittest.TestCase):
    def test_no_developer_temporary_path_in_build_or_tests(self):
        forbidden = "/tmp/" + "open" + "code"
        for directory in (".github", "tools", "tests"):
            for path in (ROOT / directory).rglob("*"):
                if "loadgen" in path.parts:
                    continue  # Local, ignored load-testing workspace.
                if path.is_file() and path.suffix in {".cpp", ".hpp", ".py", ".sh", ".yml"}:
                    with self.subTest(path=path.relative_to(ROOT)):
                        self.assertFalse(forbidden in path.read_text(), str(path))

    def test_ci_uses_runner_temporary_directory_for_static_build(self):
        workflow = (ROOT / ".github/workflows/binaries.yml").read_text()
        self.assertIn("MTDD_STATIC_ROOT: ${{ runner.temp }}/mtdd-static", workflow)


if __name__ == "__main__":
    unittest.main()
