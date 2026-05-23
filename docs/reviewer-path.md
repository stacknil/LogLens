# Reviewer Path

This path is for reviewers who want to understand LogLens quickly without reading the whole repository first.

## 30-second orientation

Read:

- [`README.md`](../README.md)
- [`docs/reviewer-brief.md`](./reviewer-brief.md)

Confirm:

- LogLens is an offline C++20 CLI for Linux authentication log analysis.
- It parses `auth.log` / `secure` style syslog input and `journalctl --output=short-full` style input.
- It emits deterministic Markdown, JSON, and optional CSV reports.
- Parser coverage telemetry is part of the output, not an internal-only detail.

Core review lens:

> Parser observability > silent detection claims.

## 5-minute artifact review

Inspect:

- [`assets/sample_auth.log`](../assets/sample_auth.log)
- [`assets/sample_journalctl_short_full.log`](../assets/sample_journalctl_short_full.log)
- [`tests/fixtures/report_contracts/syslog_legacy/report.md`](../tests/fixtures/report_contracts/syslog_legacy/report.md)
- [`tests/fixtures/report_contracts/syslog_legacy/report.json`](../tests/fixtures/report_contracts/syslog_legacy/report.json)
- [`docs/parser-contract.md`](./parser-contract.md)

Look for parser coverage fields:

- `total_input_lines`
- `total_lines`
- `skipped_blank_lines`
- `parsed_lines`
- `unparsed_lines`
- `parse_success_rate`
- `top_unknown_patterns`

Good stopping point: the reviewer can explain what LogLens parses, what it reports, and how unsupported lines remain visible.

## 15-minute local check

Run:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/loglens --mode syslog --year 2026 ./assets/sample_auth.log ./out
```

Then inspect:

- `out/report.md`
- `out/report.json`

Optional CSV check:

```bash
./build/loglens --mode syslog --year 2026 --csv ./assets/sample_auth.log ./out-csv
```

Then inspect:

- `out-csv/findings.csv`
- `out-csv/warnings.csv`

Good stopping point: the reviewer can build, test, run a sample, and compare generated artifacts with the report-contract fixtures.

## Boundaries

LogLens is intentionally narrow:

- no live collection
- no credential attack automation
- no exploitation, persistence, or offensive workflow support
- no SIEM replacement
- no cross-host correlation engine
- no incident verdict or attribution claim

Findings are rule-based triage aids. The parser boundary is the main trust boundary: recognized lines become typed events, unsupported lines become warnings and telemetry, and malformed input should fail gracefully.
