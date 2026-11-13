# codex-security-triage

Turn `@openai/codex-security` scan output into a triage report a human can
actually read — and a CI gate that fails the build on purpose.

## The problem

`codex-security` (OpenAI's open-source security CLI, trending on GitHub)
writes `findings.json` and SARIF exports. Both are machine-shaped: great for
pipelines, painful for the person who has to decide what to fix first. This
tool renders a severity-grouped Markdown report and enforces the same
`--fail-on-severity` gate the scanner uses.

## Quick start

```bash
python triage.py examples/findings.sample.json
python triage.py findings.json --fail-on-severity high --output report.md
python triage.py results.sarif --format json
```

## Example output

```
# Codex Security triage report

Total findings: **3**

- High: 1
- Medium: 1
- Low: 1

## [HIGH] SQL injection in user lookup

Location: `app/routes.py:87`
Confidence: high

User input from request.args is interpolated directly into a SQL query...

**Remediation:** Use a parameterized query (cursor.execute with
placeholders) instead of string interpolation.
```

Exit code is `0` when the gate passes, `1` when a finding meets or exceeds
`--fail-on-severity`, `2` on bad input.

## Input formats

- **findings.json** — a list, or `{"findings": [...]}`. Each finding uses
  `severity` (`critical|high|medium|low|info`), `title`, `file`, `line`,
  `description`, `remediation`, `confidence`.
- **SARIF v2.1.0** — `runs[].results[]` with rule metadata, detected by
  the presence of a top-level `runs` key.

No scanner, no API key, no network: this tool only reads output files.

## Notes

The scanner itself is not required to use this tool — the included
`examples/findings.sample.json` is modelled on the fields codex-security
documents (severity, confidence, locations, evidence, remediation).
