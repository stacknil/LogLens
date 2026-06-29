# Parser Conformance Matrix

This matrix documents the parser behavior that LogLens currently treats as
reviewable contract surface. It is derived from `src/parser.cpp`,
`src/event.hpp`, `tests/test_parser.cpp`, and the checked-in parser fixture
corpus.

The parser contract is intentionally conservative:

- recognized evidence emits a normalized `Event`
- unsupported evidence emits a parser warning, a failure category, and an unknown-pattern bucket
- unsupported evidence does not become detector input

## Input Format Matrix

| Input format | Header shape | Timestamp behavior | Parser metadata | Primary fixture |
| --- | --- | --- | --- | --- |
| `syslog_legacy` | `Mar 10 09:00:01 example-host program[pid]: message` | Requires `--year` or `timestamp.assume_year`; the supplied year is injected into the parsed timestamp | `input_mode = syslog_legacy`, `assume_year = <year>`, `timezone_present = false` | [`assets/parser_fixture_matrix_syslog.log`](../assets/parser_fixture_matrix_syslog.log) |
| `journalctl_short_full` | `Tue 2026-03-10 09:00:01 UTC example-host program[pid]: message` | Uses the embedded date and supported timezone token; supported tokens are `UTC`, `GMT`, `Z`, `+HHMM`, and `+HH:MM` style offsets | `input_mode = journalctl_short_full`, no assumed year, `timezone_present = true` | [`assets/parser_fixture_matrix_journalctl_short_full.log`](../assets/parser_fixture_matrix_journalctl_short_full.log) |

## Source Style Matrix

These source labels describe common Linux log locations and command output
styles. They are not distro-detection claims. LogLens chooses a parser mode
from the line header shape, then applies the same authentication message
classifier to the message body.

| Source style | Typical source | Parser mode | Header contract | Supported message families | Primary fixtures |
| --- | --- | --- | --- | --- | --- |
| Ubuntu / Debian `auth.log` style | `/var/log/auth.log` lines collected offline | `syslog_legacy` | BSD syslog-style timestamp without a year, followed by hostname and `program[pid]: message`; caller supplies the year | `sshd`, `sudo`, `su`, `pam_unix`, selected `pam_faillock`, selected `pam_sss` | [`assets/parser_fixture_matrix_syslog.log`](../assets/parser_fixture_matrix_syslog.log), [`assets/parser_auth_families_syslog.log`](../assets/parser_auth_families_syslog.log) |
| RHEL-family `secure` style | `/var/log/secure` lines collected offline | `syslog_legacy` | Same syslog header contract as Ubuntu / Debian `auth.log`; LogLens does not branch on distro name | `sshd`, `sudo`, `su`, `pam_unix`, selected `pam_faillock`, selected `pam_sss` | [`assets/parser_fixture_matrix_syslog.log`](../assets/parser_fixture_matrix_syslog.log), [`assets/parser_auth_families_syslog.log`](../assets/parser_auth_families_syslog.log) |
| `journalctl` short-full style | `journalctl --output=short-full` output collected offline | `journalctl_short_full` | Weekday, full date, time, timezone token, hostname, and `program[pid]: message`; embedded year is used | Same message families as `syslog_legacy` after the header is parsed | [`assets/parser_fixture_matrix_journalctl_short_full.log`](../assets/parser_fixture_matrix_journalctl_short_full.log), [`assets/parser_auth_families_journalctl_short_full.log`](../assets/parser_auth_families_journalctl_short_full.log) |

After the header is parsed, both input formats use the same authentication
message classifier. A supported message should therefore normalize to the same
event type in both formats.

## Program And PAM Family Style Matrix

This matrix lists the supported program and PAM-family styles at the message
classifier layer. "Supported" means fixture-backed selected variants, not full
coverage of every distro or PAM module wording.

| Style family | Program or tag shape | Supported variants | Expected normalized events | Unsupported boundary |
| --- | --- | --- | --- | --- |
| `sshd` | `sshd[pid]: message` or `sshd: message` | Failed password, failed password for invalid/illegal user, failed none for invalid/illegal user, direct invalid/illegal user, `input_userauth_request` invalid/illegal user, accepted password, accepted publickey, accepted keyboard-interactive/pam, failed publickey, failed keyboard-interactive/pam, maximum-authentication-attempts exceeded, and `sshd`-owned `PAM: Authentication failure` lines | `ssh_failed_password`, `ssh_invalid_user`, `ssh_accepted_password`, `ssh_accepted_publickey`, `ssh_accepted_keyboard_interactive`, `ssh_failed_publickey`, `ssh_failed_keyboard_interactive`, `ssh_max_auth_tries`, `pam_auth_failure` | Preauth close/reset, timeout/disconnection, negotiation failure, and other unsupported `sshd` messages remain parser warnings such as `sshd_connection_closed_preauth`, `sshd_timeout_or_disconnection`, `sshd_negotiation_failure`, or `sshd_other` |
| `sudo` | `sudo[pid]:    <actor> : ...` or `sudo:    <actor> : ...` | Command audit lines with `COMMAND=`, incorrect-password audit lines, user-not-in-sudoers denials, and command-not-allowed denials | `sudo_command`, `sudo_auth_failure`, `sudo_policy_denied` | Other well-formed sudo-like messages remain `sudo_other` parser warnings and do not count as sudo burst evidence |
| `su` | `su[pid]: message` or `su: message` | `FAILED SU (to <target>) <actor> on <tty>` and `Successful su for <target> by <actor>` | `su_auth_failure`, `session_opened` | Other well-formed `su` messages remain `su_other` parser warnings |
| `pam_unix` | `pam_unix(<service>:auth): ...` or `pam_unix(<service>:session): ...` | Auth failures carrying `authentication failure` plus selected session-opened lines such as sudo/su session opens | `pam_auth_failure`, `session_opened` | Session-closed and other unsupported `pam_unix` messages remain `pam_unix_session_closed` or `pam_unix_other` parser warnings |
| `pam_faillock` | `pam_faillock(<service>:auth): ...` | Selected auth failure variants: `Consecutive login failures for user ... from <ip>` and `Authentication failure for user ... from <ip>` | `pam_auth_failure` | Account-lock telemetry, auth-success telemetry, and other unmodeled variants remain `pam_faillock_account_locked`, `pam_faillock_authsucc`, or `pam_faillock_other` warnings |
| `pam_sss` | `pam_sss(<service>:auth): ...` | Selected SSSD auth failure variant: `received for user <user>: 7 (Authentication failure)` | `pam_auth_failure` | Unknown-user, auth-info-unavailable, and other unmodeled variants remain `pam_sss_unknown_user`, `pam_sss_authinfo_unavail`, or `pam_sss_other` warnings |

## Supported Event Matrix

| Evidence family | Supported message shape | Input formats | Expected normalized event | Field notes |
| --- | --- | --- | --- | --- |
| SSH failed password | `Failed password for <user> from <ip> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_failed_password` | Extracts `username` and `source_ip`. |
| SSH failed password for invalid or illegal user | `Failed password for invalid user <user> ...` or `Failed password for illegal user <user> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_invalid_user` | `illegal user` is treated as an OpenSSH wording variant of invalid user. |
| SSH failed none for invalid or illegal user | `Failed none for invalid user <user> ...` or `Failed none for illegal user <user> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_invalid_user` | `Failed none` for a regular user remains unsupported. |
| SSH direct invalid or illegal user | `Invalid user <user> from <ip>` or `Illegal user <user> from <ip>` | `syslog_legacy`, `journalctl_short_full` | `ssh_invalid_user` | Extracts `username` and `source_ip`. |
| SSH `input_userauth_request` invalid or illegal user | `input_userauth_request: invalid user <user> [preauth]` or illegal-user variant | `syslog_legacy`, `journalctl_short_full` | `ssh_invalid_user` | Extracts `username`; source IP is absent in this message shape. |
| SSH accepted password | `Accepted password for <user> from <ip> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_accepted_password` | Context event; not failure evidence by default. |
| SSH accepted publickey | `Accepted publickey for <user> from <ip> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_accepted_publickey` | Context event; key material in fixtures is sanitized. |
| SSH accepted keyboard-interactive/pam | `Accepted keyboard-interactive/pam for <user> from <ip> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_accepted_keyboard_interactive` | Context event; not failure evidence by default. |
| SSH failed publickey | `Failed publickey for <user> from <ip> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_failed_publickey` | Invalid or illegal-user wording is accepted but still normalizes as publickey failure. |
| SSH failed keyboard-interactive/pam | `Failed keyboard-interactive/pam for <user> from <ip> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_failed_keyboard_interactive` | Regular-user variant keeps the keyboard-interactive failure type. |
| SSH failed keyboard-interactive/pam for invalid or illegal user | `Failed keyboard-interactive/pam for invalid user <user> ...` or illegal-user variant | `syslog_legacy`, `journalctl_short_full` | `ssh_invalid_user` | Invalid or illegal-user variant collapses to invalid-user evidence. |
| SSH maximum authentication attempts | `maximum authentication attempts exceeded for <user> from <ip> ...` | `syslog_legacy`, `journalctl_short_full` | `ssh_max_auth_tries` | Optional leading `error:` is accepted. |
| SSH maximum authentication attempts for invalid or illegal user | `maximum authentication attempts exceeded for invalid user <user> ...` or illegal-user variant | `syslog_legacy`, `journalctl_short_full` | `ssh_invalid_user` | Optional leading `error:` is accepted. |
| `sshd`-owned PAM auth failure | `PAM: Authentication failure for <user> from <ip>` | `syslog_legacy`, `journalctl_short_full` | `pam_auth_failure` | Optional leading `error:` is accepted. |
| `sshd`-owned PAM auth failure for invalid or illegal user | `PAM: Authentication failure for invalid user <user> from <ip>` or illegal-user variant | `syslog_legacy`, `journalctl_short_full` | `ssh_invalid_user` | Keeps invalid-user evidence separate from lower-confidence PAM failure evidence. |
| `pam_unix(...:auth)` authentication failure | `authentication failure; ... rhost=<ip> ... user=<user>` | `syslog_legacy`, `journalctl_short_full` | `pam_auth_failure` | Missing `user=` or `rhost=` is allowed; fields remain empty. |
| `pam_faillock(...:auth)` consecutive login failures | `Consecutive login failures for user <user> ... from <ip>` | `syslog_legacy`, `journalctl_short_full` | `pam_auth_failure` | Selected `pam_faillock` auth failure variant. |
| `pam_faillock(...:auth)` authentication failure | `Authentication failure for user <user> from <ip>` | `syslog_legacy`, `journalctl_short_full` | `pam_auth_failure` | Selected `pam_faillock` auth failure variant. |
| `pam_sss(...:auth)` authentication failure | `received for user <user>: ... (Authentication failure)` | `syslog_legacy`, `journalctl_short_full` | `pam_auth_failure` | Extracts `username`; source IP is absent in this message shape. |
| `pam_unix(...:session)` session opened | `session opened for user <target> by <actor>(...)` | `syslog_legacy`, `journalctl_short_full` | `session_opened` | Normalized `username` is the actor after `by`. |
| Sudo command audit | `<actor> : ... COMMAND=<command>` | `syslog_legacy`, `journalctl_short_full` | `sudo_command` | Counts as sudo burst evidence by default. |
| Sudo password failure | `<actor> : 1 incorrect password attempt ...` | `syslog_legacy`, `journalctl_short_full` | `sudo_auth_failure` | Audit event; not counted as sudo burst evidence by default. |
| Sudo policy denial | `<actor> : user NOT in sudoers ...` or `<actor> : command not allowed ...` | `syslog_legacy`, `journalctl_short_full` | `sudo_policy_denied` | Audit event; not counted as sudo burst evidence by default. |
| `su` failure audit | `FAILED SU (to <target>) <actor> on <tty>` | `syslog_legacy`, `journalctl_short_full` | `su_auth_failure` | Normalized `username` is the actor. |
| `su` success audit | `Successful su for <target> by <actor>` | `syslog_legacy`, `journalctl_short_full` | `session_opened` | Normalized `username` is the actor. |

## Unsupported Bucket Matrix

Unsupported buckets are warning labels, not normalized events. The expected
normalized event is always `none`.

| Unsupported evidence | Input formats | Failure category | Expected unsupported line bucket | Expected normalized event |
| --- | --- | --- | --- | --- |
| `sshd` preauth connection closed or reset, including `Connection closed by ... [preauth]`, `Connection closed by authenticating user ... [preauth]`, and `Connection reset by ... [preauth]` | `syslog_legacy`, `journalctl_short_full` | `known_program_unknown_message` | `sshd_connection_closed_preauth` | none |
| `sshd` timeout, disconnection, or disconnect notice, including `Timeout, client not responding`, `Disconnected from ...`, and `Received disconnect ...` | `syslog_legacy`, `journalctl_short_full` | `known_program_unknown_message` | `sshd_timeout_or_disconnection` | none |
| `sshd` negotiation failure such as `Unable to negotiate with ...` | `syslog_legacy`, `journalctl_short_full` | `known_program_unknown_message` | `sshd_negotiation_failure` | none |
| Other well-formed but unsupported `sshd` messages | `syslog_legacy`, `journalctl_short_full` | `known_program_unknown_message` | `sshd_other` | none |
| `pam_unix(...:session)` session closed | `syslog_legacy`, `journalctl_short_full` | `unsupported_pam_variant` | `pam_unix_session_closed` | none |
| Other unsupported `pam_unix(...)` messages | `syslog_legacy`, `journalctl_short_full` | `unsupported_pam_variant` | `pam_unix_other` | none |
| `pam_faillock(...:auth)` account temporarily locked | `syslog_legacy`, `journalctl_short_full` | `unsupported_pam_variant` | `pam_faillock_account_locked` | none |
| `pam_faillock(...:auth)` successful authentication telemetry | `syslog_legacy`, `journalctl_short_full` | `unsupported_pam_variant` | `pam_faillock_authsucc` | none |
| Other unsupported `pam_faillock(...)` messages | `syslog_legacy`, `journalctl_short_full` | `unsupported_pam_variant` | `pam_faillock_other` | none |
| `pam_sss(...:auth)` user not known to underlying authentication module | `syslog_legacy`, `journalctl_short_full` | `unsupported_pam_variant` | `pam_sss_unknown_user` | none |
| `pam_sss(...:auth)` authentication service cannot retrieve authentication info | `syslog_legacy`, `journalctl_short_full` | `unsupported_pam_variant` | `pam_sss_authinfo_unavail` | none |
| Other unsupported `pam_sss(...)` messages | `syslog_legacy`, `journalctl_short_full` | `unsupported_pam_variant` | `pam_sss_other` | none |
| Well-formed `sudo` line that is not command, incorrect-password, or policy-denial evidence | `syslog_legacy`, `journalctl_short_full` | `known_program_unknown_message` | `sudo_other` | none |
| Well-formed `su` line that is not recognized as success or failure audit evidence | `syslog_legacy`, `journalctl_short_full` | `known_program_unknown_message` | `su_other` | none |
| Well-formed unsupported program tag | `syslog_legacy`, `journalctl_short_full` | `unknown_program` | `program_<sanitized_program>` | none |

## Header And Structural Warning Matrix

Structural failures do not reach the authentication message classifier. They
still produce parser warnings and unknown-pattern buckets through the same
coverage telemetry path.

| Failure class | Input formats | Failure category | Expected bucket | Expected normalized event |
| --- | --- | --- | --- | --- |
| Missing syslog assumed year | `syslog_legacy` | `unknown_timestamp` | `syslog_legacy_mode_requires_assume_year` | none |
| Missing syslog header fields | `syslog_legacy` | `unknown_timestamp` | `missing_syslog_header_fields` | none |
| Invalid syslog month token | `syslog_legacy` | `unknown_timestamp` | `invalid_month_token` | none |
| Invalid syslog day token | `syslog_legacy` | `unknown_timestamp` | `invalid_day_token` | none |
| Invalid time token | `syslog_legacy`, `journalctl_short_full` | `unknown_timestamp` | `invalid_time_token` | none |
| Invalid calendar date | `syslog_legacy`, `journalctl_short_full` | `unknown_timestamp` | `invalid_calendar_date` | none |
| Missing journalctl short-full header fields | `journalctl_short_full` | `unknown_timestamp` | `missing_journalctl_short_full_header_fields` | none |
| Invalid journalctl date token | `journalctl_short_full` | `unknown_timestamp` | `invalid_journalctl_date_token` | none |
| Invalid journalctl timezone token | `journalctl_short_full` | `unknown_timestamp` | `invalid_timezone_token` | none |
| Missing program/message delimiter | `syslog_legacy`, `journalctl_short_full` | `unknown_program` | `missing_program_message_delimiter` | none |
| Malformed source IP token | `syslog_legacy`, `journalctl_short_full` | `malformed_source_ip` | `malformed_source_ip` | none |

## Fixture Anchors

| Fixture | Current conformance expectation |
| --- | --- |
| [`assets/parser_fixture_matrix_syslog.log`](../assets/parser_fixture_matrix_syslog.log) | 32 analyzed lines, 23 parsed events, 9 parser warnings, unsupported buckets for SSH preauth close/reset, timeout/disconnection, negotiation failure, and `pam_unix` session-close telemetry |
| [`assets/parser_fixture_matrix_journalctl_short_full.log`](../assets/parser_fixture_matrix_journalctl_short_full.log) | Same event and warning shape as the syslog matrix, with journalctl header parsing and timezone metadata |
| [`assets/parser_auth_families_syslog.log`](../assets/parser_auth_families_syslog.log) | Selected `sshd`, `pam_unix`, `pam_faillock`, `pam_sss`, and session-opened auth-family support, plus five unsupported PAM-family telemetry buckets |
| [`assets/parser_auth_families_journalctl_short_full.log`](../assets/parser_auth_families_journalctl_short_full.log) | Same auth-family event and warning shape as the syslog auth-family fixture, with journalctl timestamp parsing |
| [`assets/noisy_auth_sample.log`](../assets/noisy_auth_sample.log) and [`tests/fixtures/parser_matrix/noisy_auth_expected.json`](../tests/fixtures/parser_matrix/noisy_auth_expected.json) | Noisy syslog coverage fixture with malformed lines, blank lines, unsupported auth-family evidence, irrelevant service lines, and locked parser quality counts |
| [`assets/mixed_auth_corpus.log`](../assets/mixed_auth_corpus.log) | 150-line sanitized mixed syslog corpus with Ubuntu / Debian-style `auth.log` and RHEL-family `secure` host labels, 90 parsed events, 50 parser warnings, 10 blank lines, and locked unknown-pattern and failure-category coverage |

## Review Rule

When this matrix changes, update the relevant parser tests and fixtures in the
same pull request. A parser behavior change should be visible in at least one of
these places:

- normalized event expectation in `tests/test_parser.cpp`
- supported fixture line under `assets/`
- unsupported warning bucket expectation
- parser failure category expectation
- report-contract fixture if the visible report shape changes
