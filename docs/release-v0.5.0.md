# LogLens v0.5.0

LogLens v0.5.0 is the Evidence Explainability Release.

This release makes the path from raw authentication evidence to bounded triage
findings easier to review. The focus is not adding more rules; it is making
parser behavior, report contracts, evidence IDs, and non-claims visible enough
for reviewers to verify.

## Highlights

- Stabilized the JSON report contract as `loglens.report.v2` with
  `schema_version` set to `2`.
- Added stable finding explainability fields so a finding can be traced back to
  its rule context and source-line evidence.
- Added a sanitized 150-line mixed auth corpus and checked-in parser coverage
  artifact for dirty syslog-style input.
- Added false-positive taxonomy and forensic-style case-study documentation for
  evidence interpretation.

## Release readiness checklist

| Requirement | Release-facing evidence | Reviewer check |
| --- | --- | --- |
| Changelog names v0.5.0 | [`CHANGELOG.md`](../CHANGELOG.md) | `v0.5.0` exists with explainability, parser observability, and case-study entries |
| Release note theme is Evidence Explainability Release | This document | Title and highlights frame v0.5 around explainability and verification, not new rule volume |
| Finding explainability fields are stable JSON contract | [`docs/report-artifacts.md`](./report-artifacts.md) and [`tests/fixtures/report_contracts/syslog_legacy/report.json`](../tests/fixtures/report_contracts/syslog_legacy/report.json) | Finding objects expose `rule_id`, `subject_kind`, `subject`, `grouping_key`, `window_start`, `window_end`, `threshold`, `observed_count`, `evidence_event_ids`, and `verdict_boundary` |
| Parser contract is release-facing | [`docs/reviewer-path.md`](./reviewer-path.md) and [`docs/parser-contract.md`](./parser-contract.md) | Reviewer path routes v0.5 review through parser behavior, parser warnings, and detection signal boundaries |
| Mixed corpus and parser coverage artifact are included | [`assets/mixed_auth_corpus.log`](../assets/mixed_auth_corpus.log) and [`assets/mixed_auth_parser_coverage.json`](../assets/mixed_auth_parser_coverage.json) | Reviewer can inspect dirty-input coverage without running the tool first |
| False-positive taxonomy is included | [`docs/false-positive-taxonomy.md`](./false-positive-taxonomy.md) | Rule-true evidence is separated from compromise, intent, attribution, and authorization claims |
| Forensic-style case study is included | [`docs/case-study-linux-auth-bruteforce.md`](./case-study-linux-auth-bruteforce.md) | Raw evidence, normalization, findings, warnings, and boundaries are explained as evidence interpretation |
| Non-claims are explicit | [Non-claims](#non-claims) | Release note states no compromise verdict, no attribution, no blocking recommendation, and no cross-host correlation |

## Stable JSON contract

`report.json` now identifies the report artifact contract with:

- `schema`: `loglens.report.v2`
- `schema_version`: `2`

Finding objects expose a stable explainability surface:

- `rule_id`
- `subject_kind`
- `subject`
- `grouping_key`
- `window_start`
- `window_end`
- `threshold`
- `observed_count`
- `evidence_event_ids`
- `verdict_boundary`

`evidence_event_ids` are deterministic local IDs such as `line:1`. They help a
reviewer trace the selected rule window back to source log lines without
claiming global event identity.

`verdict_boundary` is a machine-readable non-claim token. It keeps report output
aligned with LogLens's triage scope instead of letting a finding read like an
incident conclusion.

The contract is backed by golden fixtures for `report.md`, `report.json`,
`findings.csv`, and `warnings.csv` in
[`tests/fixtures/report_contracts`](../tests/fixtures/report_contracts). Parser
or rule changes that alter those artifacts must update the snapshots
explicitly.

## Parser observability artifacts

This release adds two reviewer-facing mixed-input artifacts:

- [`assets/mixed_auth_corpus.log`](../assets/mixed_auth_corpus.log)
- [`assets/mixed_auth_parser_coverage.json`](../assets/mixed_auth_parser_coverage.json)

The corpus is sanitized and intentionally mixed: Ubuntu / Debian-style
`auth.log`, RHEL-family `secure`-style syslog, unsupported lines, malformed
source IPs, and blank-line handling are represented together.

The parser coverage artifact lets reviewers inspect parser observability without
running the tool first. It exposes fields such as `total_input_lines`,
`parsed_lines`, `unparsed_lines`, `failure_categories`, and
`top_unknown_patterns`.

## Evidence interpretation docs

The release-facing review path now includes:

- [`docs/parser-contract.md`](./parser-contract.md) for supported inputs,
  normalized event families, parser warning categories, and detection signal
  boundaries.
- [`docs/report-artifacts.md`](./report-artifacts.md) for JSON, Markdown, and
  CSV artifact contracts.
- [`docs/false-positive-taxonomy.md`](./false-positive-taxonomy.md) for benign
  or ambiguous contexts such as NAT, bastion, internal scanner, lab replay,
  scheduled admin task, and shared account behavior.
- [`docs/incident-style-case.md`](./incident-style-case.md) for a compact trace
  from raw log lines to normalized events, finding fields, and bounded
  conclusion.
- [`docs/case-study-linux-auth-bruteforce.md`](./case-study-linux-auth-bruteforce.md)
  for a longer forensic-style evidence explanation.

## Non-claims

LogLens findings remain bounded triage signals. This release does not claim:

- no compromise verdict
- no attribution
- no blocking recommendation
- no cross-host correlation

In practical terms, a finding can show that supported evidence met a configured
rule threshold. It does not decide whether a host was compromised, who operated
the source, whether an address should be blocked, or whether activity across
hosts is related.

## Upgrade notes

No CLI migration is required for local users. Downstream consumers of
`report.json` should key off `schema` and `schema_version`, and should update
their snapshots if they depend on finding object shape.
