# Quality Gates

This document maps LogLens reviewer-facing claims to the artifacts that make
them inspectable. It is an evidence map, not a maturity badge.

The main review principle is:

> Parser observability > silent detection claims.

## Gate Map

| Claim under review | Evidence surface | Automated or repeatable gate | Good stopping point |
| --- | --- | --- | --- |
| Supported input formats are explicit | [`parser-contract.md`](./parser-contract.md), [`parser-conformance-matrix.md`](./parser-conformance-matrix.md) | `ctest --test-dir build --output-on-failure` through `test_parser`; fixture anchors in `assets/parser_fixture_matrix_syslog.log` and `assets/parser_fixture_matrix_journalctl_short_full.log` | Reviewer can name the two supported formats and see known/unknown line behavior in fixtures |
| Parser coverage is visible | [`parser-coverage-notes.md`](./parser-coverage-notes.md), [`tests/fixtures/parser_matrix/noisy_auth_expected.json`](../tests/fixtures/parser_matrix/noisy_auth_expected.json) | `test_parser` compares noisy-auth coverage output to the checked-in expected summary | Reviewer can see parsed lines, skipped blanks, warnings, failure categories, and unknown-pattern buckets |
| Unsupported evidence does not silently become detector evidence | [`parser-contract.md`](./parser-contract.md), [`rule-catalog.md`](./rule-catalog.md), [`case-study-linux-auth-bruteforce.md`](./case-study-linux-auth-bruteforce.md) | `test_parser` covers unknown-pattern warnings; `test_detector` covers signal-boundary behavior | Reviewer can explain why unsupported lines remain warnings instead of findings |
| Report artifacts are deterministic | [`report-artifacts.md`](./report-artifacts.md), report-contract fixtures under [`tests/fixtures/report_contracts`](../tests/fixtures/report_contracts) | `test_report_contracts` compares generated `report.md`, `report.json`, `findings.csv`, and `warnings.csv` against golden fixtures | Reviewer can regenerate reports and see schema or text changes as explicit snapshot diffs |
| Findings are explainable | [`rule-catalog.md`](./rule-catalog.md), [`report-artifacts.md`](./report-artifacts.md) | `test_report` checks JSON finding fields; report-contract fixtures lock `rule_id`, `window_start`, `window_end`, `threshold`, `observed_count`, `grouping_key`, and `evidence_event_ids` | Reviewer can trace a finding from rule context back to source line IDs |
| False-positive boundaries are visible | [`rule-catalog.md`](./rule-catalog.md), [`case-study-linux-auth-bruteforce.md`](./case-study-linux-auth-bruteforce.md) | Documentation review gate; detector tests ensure unsupported evidence does not inflate counts | Reviewer can state NAT, internal scanner, lab replay, shared bastion, scheduled admin task, and malformed replay boundaries |
| Parser failure taxonomy is exposed | [`parser-contract.md`](./parser-contract.md), [`parser-conformance-matrix.md`](./parser-conformance-matrix.md), [`report-artifacts.md`](./report-artifacts.md) | `test_parser`, `test_report`, `test_cli`, and `test_report_contracts` cover `failure_categories` and warning `category` output | Reviewer can distinguish timestamp, program, known-program unknown-message, malformed-source-IP, and unsupported-PAM failures |
| Local scale expectations are reproducible | [`performance-envelope.md`](./performance-envelope.md), [`scripts/benchmark-performance-envelope.ps1`](../scripts/benchmark-performance-envelope.ps1) | `pwsh -File scripts/benchmark-performance-envelope.ps1` regenerates sanitized benchmark inputs and local summary artifacts | Reviewer can reproduce the 1k/10k/100k-line envelope and understand its caveats |
| Public safety boundaries are explicit | [`README.md`](../README.md), [`SECURITY.md`](../SECURITY.md), [`repo-hardening.md`](./repo-hardening.md) | CI and CodeQL run on pull requests; repository policy keeps fixtures sanitized and defensive | Reviewer can see no live collection, exploitation, credential attack automation, incident verdict, or attribution claim |

## Local Verification Set

Use the smallest command set that answers the review question:

| Review need | Command |
| --- | --- |
| Build and unit/regression tests | `cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure` |
| Multi-config local test run | `ctest --test-dir build -C Debug --output-on-failure` |
| Report-contract snapshot verification | `ctest --test-dir build -C Debug -R report_contracts --output-on-failure` |
| Performance envelope reproduction | `pwsh -File scripts/benchmark-performance-envelope.ps1` |
| Fast performance smoke check | `pwsh -File scripts/benchmark-performance-envelope.ps1 -LineCounts 1000 -Runs 1 -WarmupRuns 0 -SkipBuild` |

## Change Review Rule

When a parser, detector, or report change modifies a claim in the gate map,
update the matching evidence surface in the same pull request:

- parser behavior change: update parser tests, fixture matrices, and parser docs
- report shape change: update report-contract fixtures and report artifact docs
- rule behavior change: update detector tests, rule catalog, and case-study text when relevant
- warning taxonomy change: update parser failure taxonomy docs and warning snapshots
- performance-envelope change: rerun the benchmark harness and record the platform/result source

If a claim has no automated gate, keep it explicit as a documentation gate
instead of implying machine enforcement.
