"""Regression tests for gcov JSON report edge cases (no compiler needed)."""

import contextlib
import gzip
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[2] / "tools" / "coverage_report.py"
SPEC = importlib.util.spec_from_file_location("coverage_report", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CoverageReportTest(unittest.TestCase):
    def test_empty_header_is_excluded_from_denominator(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            build = project / "build"
            build.mkdir()
            (build / "sample.gcda").touch()

            def gcov(*args, **kwargs):
                document = {
                    "current_working_directory": str(project),
                    "files": [
                        {"file": "include/empty.hpp", "lines": []},
                        {"file": "src/sample.cpp", "lines": [
                            {"line_number": 1, "count": 1},
                            {"line_number": 2, "count": 0},
                        ]},
                    ],
                }
                output = kwargs["cwd"] / "sample.gcov.json.gz"
                with gzip.open(output, "wt") as stream:
                    json.dump(document, stream)
                return SimpleNamespace(returncode=0)

            captured = io.StringIO()
            with patch.object(MODULE.subprocess, "run", side_effect=gcov):
                with contextlib.redirect_stdout(captured):
                    MODULE.report(build, project)
            self.assertIn("TOTAL 50.00% (1/2 executable lines)", captured.getvalue())
            self.assertNotIn("empty.hpp", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
