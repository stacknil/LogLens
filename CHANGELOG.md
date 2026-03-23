# Changelog

All notable user-visible changes should be recorded here.

## Unreleased

### Added

- Added sanitized golden `report.md` / `report.json` regression fixtures to lock report contracts.
- Added conservative parser coverage for `Accepted publickey` plus selected `pam_faillock` / `pam_sss` variants.

### Changed

- None yet.

### Fixed

- None yet.

### Docs

- None yet.

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
