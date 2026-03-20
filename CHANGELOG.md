# Changelog

All notable changes to this project will be documented in this file.

## v0.1.0

- Added parser support for `syslog_legacy` and `journalctl_short_full` authentication log input.
- Added rule-based detections for SSH brute force, multi-user probing, and bursty sudo activity.
- Added parser coverage telemetry, including parsed/unparsed counts and unknown-pattern buckets.
- Added repository automation and hardening with CI, CodeQL, pinned GitHub Actions, security policy, and Dependabot for workflow updates.
