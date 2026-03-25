# LogLens v0.3.0

LogLens v0.3.0 expands parser family coverage, strengthens deterministic regression coverage, and improves multi-host reporting while keeping the tool intentionally defensive and public-safe.

## Highlights

- broadened parser support for common Linux auth families
- strengthened sanitized corpus and golden regression coverage
- added multi-host host summaries in `report.md` and `report.json`
- added optional CSV export for findings and warnings

## Notable changes

- added parser support for `Accepted publickey` SSH successes plus selected `pam_faillock(...:auth)` and `pam_sss(...:auth)` failure variants
- expanded sanitized parser fixture matrices and added golden report-contract fixtures for Markdown, JSON, and CSV outputs
- added compact per-host summaries when one input file contains multiple hostnames, without introducing cross-host correlation or changing detector thresholds
- added explicit `--csv` output for `findings.csv` and `warnings.csv`, and kept non-CSV runs non-destructive toward existing CSV files

## Scope note

This release broadens the parser surface and improves report ergonomics, but LogLens remains a focused offline auth-log triage CLI rather than a SIEM, enrichment pipeline, or cross-host correlation platform.
