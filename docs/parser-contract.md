# Parser contract

LogLens treats parser behavior as reviewable output, not as a hidden implementation detail. A line is either recognized as a typed event, skipped as blank input, or surfaced as a warning with coverage telemetry.

The guiding rule is:

> Parser observability > silent detection claims.

## Supported input modes

| Mode | Typical source | Timestamp behavior | Review anchor |
| --- | --- | --- | --- |
| `syslog_legacy` | `auth.log` / `secure` style lines such as `Mar 10 08:11:22 example-host sshd[1234]: ...` | Requires an explicit four-digit year from `--year` or `timestamp.assume_year` | [`assets/parser_fixture_matrix_syslog.log`](../assets/parser_fixture_matrix_syslog.log) |
| `journalctl_short_full` | `journalctl --output=short-full` style lines such as `Tue 2026-03-10 08:11:22 UTC example-host sshd[1234]: ...` | Uses the embedded year and supported timezone token | [`assets/parser_fixture_matrix_journalctl_short_full.log`](../assets/parser_fixture_matrix_journalctl_short_full.log) |

Supported timezone tokens for `journalctl_short_full` are intentionally narrow: `UTC`, `GMT`, `Z`, and numeric offsets such as `+0000` or `+00:00`.

## Recognized event families

The parser currently recognizes common authentication evidence from:

- `sshd`
- `sudo`
- `su`
- `pam_unix(...)`
- selected `pam_faillock(...)` variants
- selected `pam_sss(...)` variants

Recognized SSH failure families include failed password, invalid user, illegal user, failed publickey, failed keyboard-interactive/pam, failed-none invalid-user probing, `input_userauth_request` invalid/illegal-user preauth traces, `sshd`-owned PAM authentication-failure lines, and maximum-authentication-attempts-exceeded lines. `illegal user` is treated as an OpenSSH wording variant of `invalid user`. Maximum-authentication-attempts and `sshd`-owned PAM authentication-failure lines may include OpenSSH's leading `error:` marker and still normalize into the same event family. Invalid or illegal-user variants of failed-none probing, `input_userauth_request` preauth traces, keyboard-interactive, `sshd`-owned PAM authentication failures, and maximum-authentication-attempts-exceeded lines are normalized into `ssh_invalid_user` events. Recognized SSH failures can become detection signals through the configured signal mapping.

Recognized success or audit families include accepted password, accepted publickey, accepted keyboard-interactive/pam, sudo command audit lines, sudo password failures, sudoers policy denials, su success/failure audit lines, and selected PAM session/auth lines.

## Line handling contract

| Input line outcome | Parser behavior | Report behavior |
| --- | --- | --- |
| Recognized auth line | Emits a typed `Event` with timestamp, hostname, program, optional pid, message, source IP, username, event type, and line number | Can contribute to summaries, reports, and configured detection signals |
| Blank line | Skips the line and increments `skipped_blank_lines` | Does not become a warning or parsed event |
| Malformed header | Emits a parser warning with the original line number, structural reason, and `unknown_timestamp` category | Counts toward `unparsed_lines`, `failure_categories`, and `top_unknown_patterns` |
| Well-formed but unsupported auth pattern | Emits a parser warning with a failure category and unknown-pattern bucket | Stays visible as telemetry instead of being silently ignored |

This is the main trust boundary: unsupported input should remain inspectable, even when it does not produce a finding.

Parser failure categories are intentionally coarser than unknown-pattern
buckets:

- `unknown_timestamp`
- `unknown_program`
- `known_program_unknown_message`
- `malformed_source_ip`
- `unsupported_pam_variant`

Stable unsupported-pattern buckets currently exercised by the fixture corpus include
`sshd_connection_closed_preauth`, `sshd_timeout_or_disconnection`,
`sshd_negotiation_failure`, `pam_faillock_account_locked`, and
`pam_unix_session_closed`. They are parser telemetry and warnings only; detector
signal mappings decide which parsed events can contribute to findings.

## Detection signal boundary

Parsing a line does not automatically mean it should drive a detector. LogLens keeps that boundary explicit through `AuthSignalConfig`.

Default terminal SSH failure evidence:

- `ssh_failed_password`
- `ssh_invalid_user`
- `ssh_failed_publickey`
- `ssh_failed_keyboard_interactive`
- `ssh_max_auth_tries`

Default lower-confidence attempt evidence:

- `pam_auth_failure`, which is attempt evidence but not terminal failure evidence unless configured otherwise

Default sudo burst evidence:

- `sudo_command`

Parsed successes and audit-only events remain reportable but do not count as brute-force or multi-user failure evidence by default.

## Test corpus map

| Artifact | What it proves |
| --- | --- |
| [`tests/test_parser.cpp`](../tests/test_parser.cpp) | Unit-level parser expectations, malformed-line behavior, mode aliases, fixture-matrix counts, and unknown-pattern buckets |
| [`tests/test_detector.cpp`](../tests/test_detector.cpp) | Detection signal mapping and default counting behavior after parsing |
| [`assets/parser_fixture_matrix_syslog.log`](../assets/parser_fixture_matrix_syslog.log) | Syslog known/unknown parser matrix |
| [`assets/parser_fixture_matrix_journalctl_short_full.log`](../assets/parser_fixture_matrix_journalctl_short_full.log) | Journalctl short-full known/unknown parser matrix |
| [`assets/parser_auth_families_syslog.log`](../assets/parser_auth_families_syslog.log) | Syslog PAM/auth-family parser coverage |
| [`assets/parser_auth_families_journalctl_short_full.log`](../assets/parser_auth_families_journalctl_short_full.log) | Journalctl PAM/auth-family parser coverage |
| [`assets/noisy_auth_sample.log`](../assets/noisy_auth_sample.log) and [`tests/fixtures/parser_matrix/noisy_auth_expected.json`](../tests/fixtures/parser_matrix/noisy_auth_expected.json) | Noisy syslog parser-coverage matrix for malformed, unsupported, blank, irrelevant, multi-host, and unusual-username input |
| [`tests/test_report_contracts.cpp`](../tests/test_report_contracts.cpp) | Stable report-shape expectations for generated artifacts |

## Non-goals

The parser does not try to:

- infer missing syslog years
- support every Linux authentication log variant
- classify unsupported lines as findings
- correlate across files or hosts
- produce incident verdicts

Those boundaries are intentional for the MVP. The current priority is to keep parser coverage explicit and safely extensible.
