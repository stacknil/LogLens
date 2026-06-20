# Report Artifacts

LogLens writes deterministic offline artifacts for reviewer inspection and downstream tooling.

## Artifact Set

| Artifact | When written | Review purpose |
| --- | --- | --- |
| `report.md` | Every successful run | Human-readable triage report with summary, findings, event counts, parser quality, and parser warnings |
| `report.json` | Every successful run | Machine-readable report with the same core evidence and parser telemetry |
| `findings.csv` | Only when `--csv` is set | Spreadsheet-friendly finding rows |
| `warnings.csv` | Only when `--csv` is set | Spreadsheet-friendly parser warning rows |

Without `--csv`, LogLens does not create, overwrite, or delete existing CSV files in the output directory.

## JSON Contract

The JSON report keeps parser observability visible next to findings:

- `tool`
- `input`
- `input_mode`
- `assume_year` for syslog-style input when a year is supplied
- `timezone_present`
- `parser_quality.total_input_lines`
- `parser_quality.total_lines`
- `parser_quality.skipped_blank_lines`
- `parser_quality.parsed_lines`
- `parser_quality.unparsed_lines`
- `parser_quality.parse_success_rate`
- `parser_quality.failure_categories`
- `parser_quality.top_unknown_patterns`
- `parsed_event_count`
- `warning_count`
- `finding_count`
- `event_counts`
- `host_summaries` when more than one hostname is represented
- `findings`
- `warnings`

Finding objects contain `rule_id`, `rule`, `subject_kind`, `subject`, `grouping_key`, `threshold`, `observed_count`, `event_count`, `window_start`, `window_end`, `evidence_event_ids`, `usernames`, and `summary`.

`evidence_event_ids` are deterministic local event identifiers derived from the source line number, formatted as `line:<number>`. They let reviewers trace a finding back to the normalized input events that satisfied the rule window without implying global event identity.

Warning objects contain the original `line_number`, parser `category`, and parser `reason`.

Parser failure categories are stable reviewer-facing buckets for unsupported
lines: `unknown_timestamp`, `unknown_program`,
`known_program_unknown_message`, `malformed_source_ip`, and
`unsupported_pam_variant`. They complement `top_unknown_patterns`: categories
explain the parser boundary class, while unknown-pattern buckets preserve the
more specific unsupported message shape.

## CSV Contract

The optional CSV exports intentionally stay small:

- `findings.csv`: `rule`, `subject_kind`, `subject`, `event_count`, `window_start`, `window_end`, `usernames`, `summary`
- `warnings.csv`: `kind`, `line_number`, `category`, `message`

Formula-like CSV text fields are neutralized with a leading single quote so spreadsheet tools treat them as text.

## Markdown Safety

Markdown table fields escape table separators, line breaks, HTML-sensitive characters, and control characters. Unusual log tokens should not be able to break report layout.

## Golden Fixtures

The report contracts are backed by generated fixture artifacts:

| Fixture case | Golden artifacts |
| --- | --- |
| [`syslog_legacy`](../tests/fixtures/report_contracts/syslog_legacy) | `report.md`, `report.json`, `findings.csv`, `warnings.csv` |
| [`journalctl_short_full`](../tests/fixtures/report_contracts/journalctl_short_full) | `report.md`, `report.json`, `findings.csv`, `warnings.csv` |
| [`multi_host_syslog_legacy`](../tests/fixtures/report_contracts/multi_host_syslog_legacy) | `report.md`, `report.json`, `findings.csv`, `warnings.csv` |
| [`multi_host_journalctl_short_full`](../tests/fixtures/report_contracts/multi_host_journalctl_short_full) | `report.md`, `report.json`, `findings.csv`, `warnings.csv` |

The enforcement lives in [`tests/test_report_contracts.cpp`](../tests/test_report_contracts.cpp). Parser or rule changes that alter report artifacts must update these snapshots explicitly. The focused report writer tests live in [`tests/test_report.cpp`](../tests/test_report.cpp).

## Boundaries

Reports are triage aids. They are not SIEM evidence, incident verdicts, attribution claims, or cross-host correlation output. Host summaries are compact per-host rollups; they do not change detector thresholds.
