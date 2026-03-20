# LogLens v0.1.0

LogLens v0.1.0 is the first public MVP release of the repository.

## Highlights

- Parses Linux authentication logs in both `syslog_legacy` and `journalctl_short_full` modes.
- Normalizes authentication evidence and applies configurable detections for SSH brute force, multi-user probing, and sudo burst activity.
- Reports parser coverage telemetry so unsupported lines are visible instead of silently ignored.
- Ships with deterministic Markdown and JSON reports, unit tests, CI, CodeQL, and baseline repository hardening.

## Notes

- This release is intentionally narrow in scope and focused on a clean, public-safe baseline.
- Parser coverage is limited to a small set of common `sshd`, `sudo`, and `pam_unix` patterns.
- Repository protections are designed for PR-based development with CI and CodeQL gating merges into `main`.
