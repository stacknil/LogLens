# LogLens v0.6.0 - Detection Episodes, Parser Coverage, and Audit Signals

Theme: Detection Episodes, Parser Coverage, and Audit Signals.

This release note describes the fixed v0.6 report, parser, coverage, and audit
signal contract. It does not add new detection rules.

## What Changed

- A single `rule_id`, `subject_kind`, and `subject` can emit multiple
  non-overlapping findings when evidence appears in separated detector
  episodes.
- JSON reports now use `schema: loglens.report.v3` and `schema_version: 3`.
- JSON findings include stable finding identity fields:
  - `finding_id`
  - `episode_index`
- Parser internals are organized behind a program handler registry.
- Deterministic parser property coverage and an optional libFuzzer smoke target
  cover malformed and arbitrary-byte input invariants.
- A dedicated util-linux `login` handler normalizes selected login failure and
  session messages while preserving unsupported variants as warnings.
- Privilege authentication failures from `sudo` and `su` are exposed as
  audit-only signals and do not count as detector evidence by default.
- The separated-burst contract fixture demonstrates one source IP producing two
  distinct brute-force findings in one report.

## Stable JSON Contract

`loglens.report.v3` keeps the v0.5 explainability fields and adds:

| Field | Meaning |
| --- | --- |
| `finding_id` | Deterministic report-local identifier for the selected finding, derived from the rule, subject, selected window, counts, and evidence event IDs. |
| `episode_index` | 1-based sequence number within the same `rule_id`, `subject_kind`, and `subject`. |

Existing v2 finding fields remain part of the stable explainability surface:

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

The optional CSV contract is unchanged in v0.6.

## Episode Policy

LogLens v0.6 uses cooldown-separated maximal-window episodes:

| Policy point | v0.6 behavior |
| --- | --- |
| First threshold crossing | Used to decide that an episode candidate is eligible to emit a finding. It is not necessarily the reported window. |
| Maximal window | The reported window is the highest-signal sliding window within the episode candidate. |
| Non-overlapping windows | One rule and subject can emit multiple findings, but selected episode candidates do not reuse the same matching signals. |
| Cooldown merge | Signals separated by an idle gap less than or equal to the rule window stay in the same episode candidate. A larger gap starts a new candidate. |

Episode splitting is a reporting model. It is not an incident boundary.

## Separated-Burst Fixture

The fixture
[`tests/fixtures/report_contracts/separated_bursts_syslog/input.log`](../tests/fixtures/report_contracts/separated_bursts_syslog/input.log)
contains one sanitized source IP with:

- five failed SSH attempts from `09:00:00` through `09:04:00`
- five failed SSH attempts from `15:00:00` through `15:04:00`

The expected
[`report.json`](../tests/fixtures/report_contracts/separated_bursts_syslog/report.json)
contains two `brute_force` findings for the same subject:

- `episode_index: 1`, window `2026-03-10 09:00:00` to
  `2026-03-10 09:04:00`
- `episode_index: 2`, window `2026-03-10 15:00:00` to
  `2026-03-10 15:04:00`

This fixture locks the main v0.6 behavior: repeated separated bursts are no
longer collapsed to one best window.

## Schema v2 to v3 Migration

Consumers should treat `schema` and `schema_version` as the report shape gate:

- v2: `loglens.report.v2`, `schema_version: 2`
- v3: `loglens.report.v3`, `schema_version: 3`

Consumers that keyed findings by `rule_id` and `subject` should migrate to
`finding_id`, or include `episode_index`, `window_start`, `window_end`, and
`evidence_event_ids` in their own composite key.

## Validation Surface

v0.6 is covered by:

- detector tests for separated brute-force, multi-user probing, and sudo-burst
  episodes
- detector tests for stable episode identity under unsorted input order
- detector tests for inclusive rule-window boundaries
- parser tests for malformed source-IP token classification
- parser handler registry and util-linux `login` coverage
- deterministic parser property tests and bounded fuzz smoke coverage
- audit-only privilege authentication signal behavior
- report tests for `finding_id`, `episode_index`, and schema v3 output
- golden report-contract fixtures for Markdown, JSON, and optional CSV reports

## Non-Claims

LogLens v0.6 findings remain bounded triage signals. The release preserves
these explicit non-claims:

- no compromise verdict
- no attribution
- no blocking recommendation
- no cross-host correlation

Findings remain bounded triage signals over normalized local evidence.
