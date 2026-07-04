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
- `schema`
- `schema_version`
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

Finding objects contain `finding_id`, `rule_id`, `rule`, `episode_index`, `subject_kind`, `subject`, `grouping_key`, `threshold`, `observed_count`, `event_count`, `window_start`, `window_end`, `evidence_event_ids`, `verdict_boundary`, `usernames`, and `summary`.

The stable finding explainability surface for `loglens.report.v3` is:

- `finding_id`
- `rule_id`
- `episode_index`
- `subject_kind`
- `subject`
- `grouping_key`
- `window_start`
- `window_end`
- `threshold`
- `observed_count`
- `evidence_event_ids`
- `verdict_boundary`

These fields are release-facing contract fields. Parser or rule changes that
alter their names, meanings, values, or presence must update the golden report
fixtures explicitly.

`evidence_event_ids` are deterministic local event identifiers derived from the source line number, formatted as `line:<number>`. They let reviewers trace a finding back to the normalized input events that satisfied the rule window without implying global event identity.

`finding_id` is a deterministic report-local finding identifier derived from
the rule, subject, selected window, counts, and evidence event IDs. It is
stable for the same normalized evidence and rule output, but it is not a global
case identifier.

`episode_index` is a 1-based sequence number within one `rule_id`,
`subject_kind`, and `subject`. It is meant for reviewer navigation when a rule
emits more than one finding for the same subject.

Consumers should not assume that `rule_id` plus `subject` is unique within a
report. A rule can emit multiple findings for the same subject when matching
evidence appears in time-separated detector episodes. Use `finding_id`,
`episode_index`, `window_start`, `window_end`, and `evidence_event_ids` to
distinguish episode-level findings.

`verdict_boundary` is a stable token that states what the finding must not be
read as. It keeps machine-readable findings aligned with LogLens's triage
scope:

- `triage_signal_not_compromise_or_attribution`
- `triage_signal_not_intent_or_attribution`
- `triage_signal_not_maliciousness_or_authorization`

Warning objects contain the original `line_number`, parser `category`, and parser `reason`.

`schema` and `schema_version` identify the report artifact contract, not the
application release. They are intended for downstream tooling that needs a
stable way to reject incompatible report shapes. The current JSON contract is
`loglens.report.v3` with `schema_version` set to `3`.

### Schema v2 to v3 Migration

`loglens.report.v3` keeps the v2 finding explainability fields and adds:

- `finding_id`
- `episode_index`

Downstream consumers should treat `schema` and `schema_version` as the report
shape gate. Consumers that keyed findings by `rule_id` and `subject` should
move to `finding_id`, or include `episode_index`, `window_start`, `window_end`,
and `evidence_event_ids` in their own composite key. The optional CSV contract
is unchanged in v3.

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
| [`separated_bursts_syslog`](../tests/fixtures/report_contracts/separated_bursts_syslog) | `report.md`, `report.json`, `findings.csv`, `warnings.csv` |

The enforcement lives in [`tests/test_report_contracts.cpp`](../tests/test_report_contracts.cpp). Parser or rule changes that alter report artifacts must update these snapshots explicitly. This includes changes to stable finding explainability fields, parser coverage fields, warning categories, CSV columns, or Markdown report layout. The focused report writer tests live in [`tests/test_report.cpp`](../tests/test_report.cpp).

## Boundaries

Reports are triage aids. They are not SIEM evidence, incident verdicts, attribution claims, or cross-host correlation output. Host summaries are compact per-host rollups; they do not change detector thresholds.
