"""Tests for triage.py (stdlib only)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import triage  # noqa: E402

SAMPLE = ROOT / "examples" / "findings.sample.json"


def run(*args):
    return subprocess.run(
        [sys.executable, "triage.py", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


class TestLoad(unittest.TestCase):
    def test_sample_loads_three_findings(self):
        findings = triage.load(SAMPLE)
        self.assertEqual(len(findings), 3)
        self.assertEqual(
            sorted(f["severity"] for f in findings), ["high", "low", "medium"])

    def test_sarif_loads(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"rules": [
                    {"id": "SEC001", "name": "Hardcoded secret",
                     "help": {"text": "Move the secret to env vars."}}]}},
                "results": [{
                    "ruleId": "SEC001", "level": "error",
                    "message": {"text": "Hardcoded API key."},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "config.py"},
                        "region": {"startLine": 7}}}],
                }],
            }],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False) as f:
            json.dump(sarif, f)
            path = Path(f.name)
        findings = triage.load(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["file"], "config.py")
        self.assertEqual(findings[0]["line"], 7)


class TestCli(unittest.TestCase):
    def test_markdown_report(self):
        result = run(str(SAMPLE))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Total findings: **3**", result.stdout)
        self.assertIn("[HIGH] SQL injection in user lookup", result.stdout)

    def test_gate_blocks_high(self):
        result = run(str(SAMPLE), "--fail-on-severity", "high")
        self.assertEqual(result.returncode, 1)
        self.assertIn("gate failed", result.stderr)

    def test_gate_passes_when_below_threshold(self):
        result = run(str(SAMPLE), "--fail-on-severity", "critical")
        self.assertEqual(result.returncode, 0)

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.md"
            result = run(str(SAMPLE), "--output", str(out))
            self.assertEqual(result.returncode, 0)
            self.assertIn("SQL injection", out.read_text(encoding="utf-8"))

    def test_json_format(self):
        result = run(str(SAMPLE), "--format", "json")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["summary"]["total"], 3)
        self.assertEqual(data["summary"]["by_severity"]["high"], 1)


if __name__ == "__main__":
    unittest.main()
