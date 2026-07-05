# Changelog

All notable user-visible changes should be recorded here.

## Unreleased

### Added

- Added stable JSON finding identity fields: `finding_id` and
  `episode_index`.
- Added a separated-burst syslog report-contract fixture where one source IP
  produces two time-separated brute-force findings.
- Added detector regression coverage for stable episode identity under unsorted
  input order and inclusive window-boundary behavior.
- Added parser regression coverage for malformed source-IP token
  classification.
- Added deterministic parser property tests for registry-order independence,
  generated malformed tokens, failure taxonomy stability, and arbitrary-byte
  result invariants.
- Added an optional Clang libFuzzer parser target with a sanitized seed corpus
  and bounded Ubuntu CI smoke campaign.
- Added a dedicated util-linux `login` handler for selected failed-login,
  retry-exhaustion, session-failure, local-login, and root-login messages.
- Expanded the sanitized mixed auth corpus from 150 to 160 lines with ten
  fixture-backed `login` records and updated parser coverage telemetry.

### Changed

- Refactored parser internals into timestamp, source-envelope, program-dispatch,
  program-handler, and failure-classifier modules behind the unchanged
  `AuthLogParser` interface.
- Detector rules now emit separate findings for time-separated detection
  episodes within the same rule subject instead of collapsing each subject to a
  single best window.
- Bumped the JSON report artifact contract from `loglens.report.v2` /
  `schema_version` 2 to `loglens.report.v3` / `schema_version` 3 for finding
  identity fields.

### Fixed

- None yet.

### Docs

- Documented detection episode semantics in the rule catalog and report artifact
  contract notes.
- Added the v0.6 Detection Episode Semantics release note and schema v2 to v3
  migration guidance.

## v0.5.0

### Added

- Stabilized the JSON report artifact contract as `loglens.report.v2` with
  `schema_version` set to `2`.
- Added finding explainability fields to JSON findings, including `rule_id`,
  `subject_kind`, `subject`, `grouping_key`, `window_start`, `window_end`,
  `threshold`, `observed_count`, `evidence_event_ids`, and `verdict_boundary`.
- Added sanitized golden `report.md`, `report.json`, `findings.csv`, and
  `warnings.csv` regression fixtures to lock report contracts.
- Added a 150-line sanitized mixed auth corpus fixture covering Ubuntu /
  Debian-style `auth.log`, RHEL-family `secure`-style syslog, unknown lines,
  malformed source IPs, and blank-line handling.
- Added a reviewer-facing parser coverage JSON artifact for the mixed auth
  corpus.

### Changed

- Made parser coverage telemetry and finding explainability part of the
  release-facing review path instead of internal-only implementation detail.

### Fixed

- None.

### Docs

- Added release notes for the v0.5 Evidence Explainability Release.
- Added a release readiness checklist that maps v0.5 requirements to reviewer
  evidence and stopping points.
- Added a one-page incident-style case that traces raw SSH evidence through
  normalized events and finding fields to a bounded conclusion.
- Added a rule-by-rule false-positive taxonomy for NAT, bastion, internal scanner,
  lab replay, scheduled admin task, and shared-account contexts.
- Added forensic-style case-study coverage for Linux auth brute-force evidence
  interpretation.
- Expanded the parser conformance matrix with explicit Ubuntu / Debian
  `auth.log`, RHEL-family `secure`, `journalctl --output=short-full`, `sshd`,
  `sudo`, `pam_unix`, `pam_faillock`, and `pam_sss` style coverage.

## v0.4.0

### Added

- Added optional CSV export for `findings.csv` and `warnings.csv`.
- Added single-host and multi-host CSV regression coverage.
- Added `.gitattributes` guardrails to reduce future line-ending drift.

### Changed

- None.

### Fixed

- Preserved default Markdown and JSON behavior when `--csv` is not requested.

### Docs

- None.

## v0.3.0

### Added

- Broadened parser support for common Linux auth families by adding `Accepted publickey` handling plus selected `pam_faillock` and `pam_sss` auth failure variants.
- Added compact host-level summaries to `report.md` and `report.json` for multi-host inputs.
- Added optional CSV export for findings and warnings behind an explicit `--csv` flag.
- Added sanitized golden report-contract fixtures to lock deterministic Markdown, JSON, and CSV outputs.

### Changed

- Strengthened sanitized regression coverage with expanded parser fixture corpora and golden report-contract checks.

### Fixed

- Non-CSV runs now preserve pre-existing `findings.csv` and `warnings.csv` files instead of deleting them by default.

### Docs

- Synced release-facing documentation in `README.md` and added `docs/release-v0.3.0.md` for GitHub Release copy.

## v0.2.0

### Added

- Added dedicated sanitized parser fixture matrices for both `syslog_legacy` and `journalctl_short_full`, expanding `sshd` and `pam_unix` coverage.
- Added deterministic unknown-line telemetry coverage for unsupported parser inputs and unknown-pattern buckets.

### Changed

- Moved sudo handling onto the signal layer so detectors consume one unified normalized input model.
- Kept detector thresholds and the existing report schema stable while simplifying internal detector semantics.

### Fixed

- None.

### Docs

- Improved release-facing documentation in `README.md`, added `docs/release-process.md`, and formalized changelog discipline for future releases.

## v0.1.0

### Added

- Parser support for `syslog_legacy` and `journalctl_short_full` authentication log input.
- Rule-based detections for SSH brute force, multi-user probing, and sudo burst activity.
- Parser coverage telemetry including parsed/unparsed counts and unknown-pattern buckets.
- Repository automation and hardening with CI, CodeQL, pinned GitHub Actions, security policy, and Dependabot for workflow updates.

### Changed

- Established deterministic Markdown and JSON reporting for the MVP release.

### Fixed

- None.

### Docs

- Added CI, CodeQL, repository hardening guidance, and release-facing project documentation for the first public release.
