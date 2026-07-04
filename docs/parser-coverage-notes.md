# Parser coverage notes

LogLens parser coverage is intentionally visible. Noisy logs should produce a useful coverage shape instead of a quiet success claim.

## Noisy auth matrix

[`assets/noisy_auth_sample.log`](../assets/noisy_auth_sample.log) is a sanitized `syslog_legacy` sample for reviewer inspection. It mixes recognized authentication evidence with common log noise:

- malformed timestamp evidence
- unsupported but bucketed `sshd` preauth, disconnect, and negotiation lines
- partial PAM evidence that is either lower-confidence parsed evidence or telemetry-only warning evidence
- sudo denial variants that still become typed audit events
- empty, blank, rotated, and irrelevant service lines
- multiple hosts and intentionally unusual synthetic usernames

The locked expected coverage summary lives in [`tests/fixtures/parser_matrix/noisy_auth_expected.json`](../tests/fixtures/parser_matrix/noisy_auth_expected.json). It focuses on parser quality fields rather than detector findings:

- `total_input_lines`: 27
- `skipped_blank_lines`: 3
- `parsed_lines`: 8
- `unparsed_lines`: 16
- `parse_success_rate`: 0.3333333333
- `failure_categories`: coarse parser boundary categories for unsupported lines
- `top_unknown_patterns`: the five most common unsupported-pattern buckets

## Mixed auth corpus

[`assets/mixed_auth_corpus.log`](../assets/mixed_auth_corpus.log) is a 150-line sanitized `syslog_legacy` corpus for dirty-input review. It mixes Ubuntu / Debian `auth.log`-style and RHEL-family `secure`-style host labels while keeping the same BSD syslog header contract. This is a parser-observability fixture, not a claim of complete distro coverage.

The corpus repeats ten small evidence batches. Each batch includes recognized `sshd`, `sudo`, `su`, `pam_unix`, `pam_faillock`, and `pam_sss` evidence; unsupported `sshd` preauth and `pam_unix` session-close telemetry; an unsupported service program; a malformed source IP; an invalid timestamp; and one blank line.

For reviewer inspection without running the test suite, [`assets/mixed_auth_parser_coverage.json`](../assets/mixed_auth_parser_coverage.json) captures the deterministic parser coverage view for this corpus: parser-quality counters, normalized event-type counts, unknown-pattern buckets, failure categories, and warning line references.

Locked parser expectations:

- `total_input_lines`: 150
- `skipped_blank_lines`: 10
- `parsed_lines`: 90
- `unparsed_lines`: 50
- normalized event counts: 10 invalid-user SSH failures, 10 failed-publickey SSH events, 10 accepted-publickey SSH events, 10 sudo command events, 10 sudo auth failures, 30 PAM auth failures, and 10 `su` auth failures
- `failure_categories`: 10 each for `known_program_unknown_message`, `malformed_source_ip`, `unknown_program`, `unknown_timestamp`, and `unsupported_pam_variant`
- `top_unknown_patterns`: 10 each for `invalid_month_token`, `malformed_source_ip`, `pam_unix_session_closed`, `program_cron`, and `sshd_connection_closed_preauth`

## Reading the numbers

A low parse success rate is not automatically a bug for this fixture. The sample is deliberately noisy, and the useful property is that unsupported evidence remains explainable through `warnings`, `failure_categories`, and `top_unknown_patterns`.

The matrix should stay defensive and public-safe: use documentation IP ranges, synthetic hostnames, and synthetic usernames only.
