# Reviewer brief

## Problem

Linux auth logs are noisy, format-sensitive, and easy to parse incorrectly. Reviewers often see detectors that claim findings without making parser limits or coverage visible.

## What it does

`LogLens` is a C++20 offline CLI for Linux authentication evidence. It parses `auth.log` / `secure` style syslog input and `journalctl --output=short-full` style input, normalizes the evidence, applies small rule-based detections, and emits deterministic Markdown and JSON reports with parser coverage telemetry.

## Reviewer Evidence

- Reproducible command: `./build/loglens --mode syslog --year 2026 ./assets/sample_auth.log ./out`
- Deterministic outputs: `report.md`, `report.json`, optional `findings.csv`, optional `warnings.csv`, and parser coverage telemetry.
- Tests / CI: CTest coverage plus GitHub Actions CI on Ubuntu and Windows; CodeQL is required on protected main.
- Release evidence: changelog, release process docs, versioned release notes, and GitHub release artifacts.
- Non-goals: live collection, SIEM replacement, cross-host correlation, exploitation, credential attack automation, or incident verdicts.

## Quick run

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/loglens --mode syslog --year 2026 ./assets/sample_auth.log ./out
```

## Sample output

The bundled sanitized sample produces `out/report.md` and `out/report.json`.

The current README-documented summary excerpt is:

- input mode: `syslog_legacy`
- parsed events: `14`
- findings: `3`
- parser warnings: `2`

When `--csv` is enabled, the CLI also emits `findings.csv` and `warnings.csv`.

## What this proves

- C++ implementation discipline for a defensive CLI instead of a throwaway script
- parser observability, not just detection output
- deterministic report generation with stable review artifacts
- repository hygiene through CI, tests, and CodeQL

## Safety / boundaries

- offline log review only
- defensive and public-safe scope
- no exploitation, persistence, credential attack automation, or live collection
- findings are triage aids, not incident verdicts

## Limitations

- parser coverage is intentionally narrow and auth-family focused
- no cross-host correlation or SIEM-like aggregation
- `syslog_legacy` requires an explicit year
- rules are threshold-based and conservative

## Next milestone

Broaden supported auth patterns and keep parser-coverage evidence as visible as the finding output.
