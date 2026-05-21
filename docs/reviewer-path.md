# Reviewer path

LogLens is easiest to review when the first question is explicit. The project is not trying to be a SIEM or a broad Linux auth parser; it is a C++20 offline CLI that makes authentication parsing, detection boundaries, and report artifacts inspectable.

The core review lens is:

> Parser observability > silent detection claims.

That means unsupported and malformed lines should be visible as parser telemetry or warnings instead of disappearing behind confident-looking findings.

## First choose the review question

| Review question | Start here | Good stopping point |
| --- | --- | --- |
| What is LogLens? | [`README.md`](../README.md) and [`docs/reviewer-brief.md`](./reviewer-brief.md) | Can state the defensive scope, CLI shape, and non-goals |
| What log formats are supported? | README Detections plus [`docs/parser-contract.md`](./parser-contract.md) | Can name `syslog_legacy` and `journalctl_short_full`, including the explicit year requirement for syslog |
| What artifacts does it produce? | README Run / Sample Output plus [`tests/test_report_contracts.cpp`](../tests/test_report_contracts.cpp) | Can inspect `report.md`, `report.json`, `findings.csv`, and `warnings.csv` |
| Can the parser behavior be trusted? | [`docs/parser-contract.md`](./parser-contract.md), [`tests/test_parser.cpp`](../tests/test_parser.cpp), [`assets/parser_fixture_matrix_syslog.log`](../assets/parser_fixture_matrix_syslog.log), and [`assets/parser_fixture_matrix_journalctl_short_full.log`](../assets/parser_fixture_matrix_journalctl_short_full.log) | Can see known auth lines become events and unknown lines become warnings / telemetry |
| Is it production-ready? | README Known Limitations, [`CHANGELOG.md`](../CHANGELOG.md), and [`docs/release-v0.1.0.md`](./release-v0.1.0.md) | Can state MVP boundaries and what should not be inferred from the findings |

## Ten-minute review path

1. Read the README through Detections and Known Limitations.
2. Skim the reviewer brief for problem, evidence, and boundaries.
3. Run the sample command from the README or reviewer brief.
4. Open `report.md` and `report.json` in the output directory.
5. Compare parser fixture inputs with `docs/parser-contract.md` and `tests/test_parser.cpp` to see recognized and unsupported line handling.

## What to look for

- Parser correctness is treated as a first-class part of the tool, not a hidden precondition.
- Reports include coverage metrics such as parsed, unparsed, warning, and unknown-pattern counts.
- Detection rules are small, centralized, configurable, and threshold-based.
- Unsupported lines remain reviewable through warnings instead of becoming silent misses.
- Public examples use sanitized hosts, users, and documentation IP ranges.

## Good review outcome

A reviewer should be able to say:

- LogLens is an offline defensive log-analysis CLI for Linux authentication evidence.
- It supports syslog-style auth logs and `journalctl --output=short-full` style logs.
- It produces deterministic Markdown, JSON, and optional CSV artifacts.
- It makes parser coverage visible before asking the reviewer to trust detection claims.
- It is a focused MVP, not a production SIEM, host correlation engine, or incident verdict system.
