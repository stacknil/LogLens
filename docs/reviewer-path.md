# Reviewer Path

This path is for reviewers who want to understand LogLens quickly without reading the whole repository first.

## First choose the review question

| Review question | Start here | Good stopping point |
| --- | --- | --- |
| What is LogLens? | [`README.md`](../README.md) and [`docs/reviewer-brief.md`](./reviewer-brief.md) | Can state scope, supported inputs, outputs, and non-goals |
| What changed in v0.5? | [`docs/release-v0.5.0.md`](./release-v0.5.0.md) | Can explain the Evidence Explainability Release theme and its non-claims |
| What log formats are supported? | [`docs/parser-contract.md`](./parser-contract.md) | Can name `syslog_legacy` and `journalctl_short_full` behavior |
| What artifacts does it produce? | [`docs/report-artifacts.md`](./report-artifacts.md) and report-contract fixtures | Can inspect Markdown, JSON, and optional CSV outputs |
| How do rules use evidence? | [`docs/rule-catalog.md`](./rule-catalog.md) | Can explain grouping keys, windows, thresholds, and unsupported-evidence boundaries |
| Can I trace one finding end to end? | [`docs/incident-style-case.md`](./incident-style-case.md) | Can follow raw lines through normalization and rule fields to a bounded conclusion |
| What benign context can match a rule? | [`docs/false-positive-taxonomy.md`](./false-positive-taxonomy.md) | Can distinguish rule-true evidence from compromise, intent, attribution, or authorization claims |
| Can the parser behavior be trusted? | Parser contract, fixture matrix, and [`assets/mixed_auth_parser_coverage.json`](../assets/mixed_auth_parser_coverage.json) | Can see known, unknown, and malformed line handling |
| What proves the main claims? | [`docs/quality-gates.md`](./quality-gates.md) | Can map claims to tests, fixtures, docs, and repeatable commands |
| How should a finding be interpreted? | [`docs/case-study-linux-auth-bruteforce.md`](./case-study-linux-auth-bruteforce.md) | Can trace raw evidence to normalized events, findings, warnings, and non-goals |
| How does it behave on larger local inputs? | [`docs/performance-envelope.md`](./performance-envelope.md) | Can state the local 1k/10k/100k-line envelope and its caveats |

## 30-second orientation

Read:

- [`README.md`](../README.md)
- [`docs/reviewer-brief.md`](./reviewer-brief.md)
- [`docs/release-v0.5.0.md`](./release-v0.5.0.md)

Confirm:

- LogLens is an offline C++20 CLI for Linux authentication log analysis.
- It parses `auth.log` / `secure` style syslog input and `journalctl --output=short-full` style input.
- It emits deterministic Markdown, JSON, and optional CSV reports.
- Parser coverage telemetry is part of the output, not an internal-only detail.

Core review lens:

> Parser observability > silent detection claims.

## v0.5 release-facing route

Start with [`docs/release-v0.5.0.md`](./release-v0.5.0.md), then inspect:

- [`docs/parser-contract.md`](./parser-contract.md)
- [`docs/report-artifacts.md`](./report-artifacts.md)
- [`tests/fixtures/report_contracts/syslog_legacy/report.json`](../tests/fixtures/report_contracts/syslog_legacy/report.json)
- [`assets/mixed_auth_corpus.log`](../assets/mixed_auth_corpus.log)
- [`assets/mixed_auth_parser_coverage.json`](../assets/mixed_auth_parser_coverage.json)
- [`docs/false-positive-taxonomy.md`](./false-positive-taxonomy.md)
- [`docs/case-study-linux-auth-bruteforce.md`](./case-study-linux-auth-bruteforce.md)

Good stopping point: the reviewer can name the stable finding explainability
fields, explain how parser coverage remains visible for unknown lines, and state
that findings are bounded triage signals with no compromise verdict,
attribution, blocking recommendation, or cross-host correlation claim.

Use the release note's
[`Release readiness checklist`](./release-v0.5.0.md#release-readiness-checklist)
as the compact pass/fail map for the v0.5 scope.

## 5-minute artifact review

Inspect:

- [`assets/sample_auth.log`](../assets/sample_auth.log)
- [`assets/sample_journalctl_short_full.log`](../assets/sample_journalctl_short_full.log)
- [`tests/fixtures/report_contracts/syslog_legacy/report.md`](../tests/fixtures/report_contracts/syslog_legacy/report.md)
- [`tests/fixtures/report_contracts/syslog_legacy/report.json`](../tests/fixtures/report_contracts/syslog_legacy/report.json)
- [`docs/release-v0.5.0.md`](./release-v0.5.0.md)
- [`docs/report-artifacts.md`](./report-artifacts.md)
- [`docs/parser-contract.md`](./parser-contract.md)
- [`assets/mixed_auth_corpus.log`](../assets/mixed_auth_corpus.log)
- [`assets/mixed_auth_parser_coverage.json`](../assets/mixed_auth_parser_coverage.json)
- [`docs/quality-gates.md`](./quality-gates.md)
- [`docs/incident-style-case.md`](./incident-style-case.md)
- [`docs/rule-catalog.md`](./rule-catalog.md)
- [`docs/false-positive-taxonomy.md`](./false-positive-taxonomy.md)
- [`docs/case-study-linux-auth-bruteforce.md`](./case-study-linux-auth-bruteforce.md)

Look for the evidence route:

- raw log line
- normalized event
- signal mapping boundary
- rule grouping, window, and threshold
- false-positive hypotheses and required corroborating context
- report finding or parser warning

Look for parser coverage fields:

- `total_input_lines`
- `total_lines`
- `skipped_blank_lines`
- `parsed_lines`
- `unparsed_lines`
- `parse_success_rate`
- `failure_categories`
- `top_unknown_patterns`

Good stopping point: the reviewer can explain what LogLens parses, how rules count supported evidence, what the reports contain, and how unsupported lines remain visible without becoming findings.

## 15-minute local check

Run:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/loglens --mode syslog --year 2026 ./assets/sample_auth.log ./out
```

For Visual Studio or other multi-config generators, use
`ctest --test-dir build -C Debug --output-on-failure` for the test step.

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
