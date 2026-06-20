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

## Reading the numbers

A low parse success rate is not automatically a bug for this fixture. The sample is deliberately noisy, and the useful property is that unsupported evidence remains explainable through `warnings`, `failure_categories`, and `top_unknown_patterns`.

The matrix should stay defensive and public-safe: use documentation IP ranges, synthetic hostnames, and synthetic usernames only.
