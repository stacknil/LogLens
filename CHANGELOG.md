# Changelog

All notable user-visible changes should be recorded here.

## Unreleased

### Added

- None yet.

### Changed

- None yet.

### Fixed

- None yet.

### Docs

- None yet.

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
