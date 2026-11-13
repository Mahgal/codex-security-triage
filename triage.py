#!/usr/bin/env python3
"""codex-security-triage — turn @openai/codex-security findings into a
human-readable triage report and a CI gate.

codex-security (openai/codex-security) writes findings.json (and SARIF
exports) after a scan. This tool consumes either format and produces:

* a Markdown report grouped by severity, with file:line, confidence,
  evidence and remediation per finding;
* an optional ``--fail-on-severity`` gate (same semantics as the scanner's
  own flag): exit 1 when any finding meets or exceeds the threshold.

Expected findings.json shape (list, or {"findings": [...]}):
    {"severity": "high", "title": "SQL injection", "file": "app.py",
     "line": 42, "description": "...", "remediation": "...",
     "confidence": "high"}

SARIF v2.1.0 is also accepted (runs[].results[] with ruleId, level,
message.text and locations). The scanner itself is NOT required — this
tool only reads its output files.

Usage:
    python triage.py examples/findings.sample.json
    python triage.py findings.json --fail-on-severity high --output report.md
    python triage.py results.sarif --format json
"""

import argparse
import json
import sys
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}
SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def normalize_severity(value) -> str:
    value = str(value or "info").lower()
    return value if value in SEVERITY_RANK else "info"


def normalize_finding(raw: dict) -> dict:
    return {
        "severity": normalize_severity(raw.get("severity")),
        "title": str(raw.get("title") or raw.get("ruleId") or "Untitled finding"),
        "file": str(raw.get("file") or ""),
        "line": raw.get("line") or 0,
        "description": str(raw.get("description") or raw.get("message") or ""),
        "remediation": str(raw.get("remediation") or ""),
        "confidence": str(raw.get("confidence") or "unknown"),
    }


def load_findings_json(data) -> list[dict]:
    items = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError("findings.json must be a list or {'findings': [...]}")
    return [normalize_finding(item) for item in items]


def load_sarif(data: dict) -> list[dict]:
    findings = []
    for run in data.get("runs", []):
        rules = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rules[rule.get("id")] = rule
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            location = {}
            try:
                location = result["locations"][0]["physicalLocation"]
            except (KeyError, IndexError, TypeError):
                pass
            region = location.get("region", {})
            findings.append(normalize_finding({
                "severity": SARIF_LEVEL.get(result.get("level", ""), "medium"),
                "title": rule.get("name") or rule_id or "Untitled finding",
                "file": location.get("artifactLocation", {}).get("uri", ""),
                "line": region.get("startLine", 0),
                "description": result.get("message", {}).get("text", ""),
                "remediation": rule.get("help", {}).get("text", ""),
            }))
    return findings


def load(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "runs" in data:
        return load_sarif(data)
    return load_findings_json(data)


def summarize(findings: list[dict]) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    return {"total": len(findings), "by_severity": counts}


def render_markdown(findings: list[dict]) -> str:
    summary = summarize(findings)
    lines = ["# Codex Security triage report", "",
             f"Total findings: **{summary['total']}**", ""]
    for sev in SEVERITY_ORDER:
        if summary["by_severity"][sev]:
            lines.append(f"- {sev.capitalize()}: {summary['by_severity'][sev]}")
    lines.append("")
    if not findings:
        lines.append("No findings. 🎉")
        return "\n".join(lines) + "\n"
    ordered = sorted(findings, key=lambda f: SEVERITY_RANK[f["severity"]])
    for finding in ordered:
        where = finding["file"]
        if finding["line"]:
            where += f":{finding['line']}"
        lines += [f"## [{finding['severity'].upper()}] {finding['title']}", ""]
        if where:
            lines.append(f"Location: `{where}`")
        lines.append(f"Confidence: {finding['confidence']}")
        if finding["description"]:
            lines += ["", finding["description"]]
        if finding["remediation"]:
            lines += ["", f"**Remediation:** {finding['remediation']}"]
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", type=Path,
                        help="codex-security findings.json or SARIF export")
    parser.add_argument("--fail-on-severity", choices=SEVERITY_ORDER,
                        help="exit 1 when a finding meets/exceeds this level")
    parser.add_argument("--output", type=Path, help="write Markdown report here")
    parser.add_argument("--format", choices=("md", "json"), default="md")
    args = parser.parse_args(argv)

    try:
        findings = load(args.input)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = summarize(findings)
    if args.format == "json":
        print(json.dumps({"summary": summary, "findings": findings}, indent=2))
    else:
        report = render_markdown(findings)
        if args.output:
            args.output.write_text(report, encoding="utf-8")
            print(f"Wrote {args.output} ({summary['total']} findings)")
        else:
            print(report, end="")

    if args.fail_on_severity:
        threshold = SEVERITY_RANK[args.fail_on_severity]
        breached = [f for f in findings
                    if SEVERITY_RANK[f["severity"]] <= threshold]
        if breached:
            print(f"gate failed: {len(breached)} finding(s) at or above "
                  f"{args.fail_on_severity}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
