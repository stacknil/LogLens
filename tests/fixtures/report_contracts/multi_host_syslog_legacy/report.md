# LogLens Report

## Summary

- Input: `tests/fixtures/report_contracts/multi_host_syslog_legacy/input.log`
- Input mode: syslog_legacy
- Assume year: 2026
- Timezone present: false
- Total input lines: 17
- Total lines: 17
- Skipped blank lines: 0
- Parsed lines: 12
- Unparsed lines: 5
- Parse success rate: 70.59%
- Parsed events: 12
- Findings: 3
- Parser warnings: 5

## Host Summary

| Host | Parsed Events | Findings | Warnings |
| --- | ---: | ---: | ---: |
| alpha-host | 7 | 2 | 2 |
| beta-host | 5 | 1 | 3 |

## Findings

| Rule | Subject | Count | Window | Notes |
| --- | --- | ---: | --- | --- |
| brute_force | 203.0.113.10 | 5 | 2026-03-11 09:00:00 -> 2026-03-11 09:04:05 | 5 failed SSH attempts from 203.0.113.10 within 10 minutes. |
| multi_user_probing | 203.0.113.10 | 5 | 2026-03-11 09:00:00 -> 2026-03-11 09:04:05 | 203.0.113.10 targeted 5 usernames within 15 minutes. Usernames: admin, deploy, guest, root, test |
| sudo_burst | alice | 3 | 2026-03-11 09:11:00 -> 2026-03-11 09:14:15 | alice ran 3 sudo commands within 5 minutes. |

## Event Counts

| Event Type | Count |
| --- | ---: |
| ssh_failed_password | 3 |
| ssh_accepted_password | 1 |
| ssh_accepted_publickey | 1 |
| ssh_invalid_user | 2 |
| pam_auth_failure | 2 |
| sudo_command | 3 |

## Parser Quality

| Unknown Pattern | Count |
| --- | ---: |
| pam_sss_unknown_user | 1 |
| pam_unix_session_closed | 1 |
| sshd_connection_closed_preauth | 1 |
| sshd_negotiation_failure | 1 |
| sshd_timeout_or_disconnection | 1 |

| Failure Category | Count |
| --- | ---: |
| known_program_unknown_message | 3 |
| unsupported_pam_variant | 2 |

## Parser Warnings

| Line | Category | Reason |
| ---: | --- | --- |
| 12 | unsupported_pam_variant | unrecognized auth pattern: pam_sss_unknown_user |
| 14 | known_program_unknown_message | unrecognized auth pattern: sshd_connection_closed_preauth |
| 15 | known_program_unknown_message | unrecognized auth pattern: sshd_timeout_or_disconnection |
| 16 | unsupported_pam_variant | unrecognized auth pattern: pam_unix_session_closed |
| 17 | known_program_unknown_message | unrecognized auth pattern: sshd_negotiation_failure |
