# LogLens Report

## Summary

- Input: `tests/fixtures/report_contracts/syslog_legacy/input.log`
- Input mode: syslog_legacy
- Assume year: 2026
- Timezone present: false
- Total lines: 16
- Parsed lines: 14
- Unparsed lines: 2
- Parse success rate: 87.50%
- Parsed events: 14
- Findings: 3
- Parser warnings: 2

## Findings

| Rule | Subject | Count | Window | Notes |
| --- | --- | ---: | --- | --- |
| brute_force | 203.0.113.10 | 5 | 2026-03-10 08:11:22 -> 2026-03-10 08:18:05 | 5 failed SSH attempts from 203.0.113.10 within 10 minutes. |
| multi_user_probing | 203.0.113.10 | 5 | 2026-03-10 08:11:22 -> 2026-03-10 08:18:05 | 203.0.113.10 targeted 5 usernames within 15 minutes. Usernames: admin, deploy, guest, root, test |
| sudo_burst | alice | 3 | 2026-03-10 08:21:00 -> 2026-03-10 08:24:15 | alice ran 3 sudo commands within 5 minutes. |

## Event Counts

| Event Type | Count |
| --- | ---: |
| ssh_failed_password | 4 |
| ssh_accepted_password | 1 |
| ssh_invalid_user | 3 |
| ssh_failed_publickey | 1 |
| pam_auth_failure | 1 |
| session_opened | 1 |
| sudo_command | 3 |

## Parser Quality

| Unknown Pattern | Count |
| --- | ---: |
| sshd_connection_closed_preauth | 1 |
| sshd_timeout_or_disconnection | 1 |

## Parser Warnings

| Line | Reason |
| ---: | --- |
| 15 | unrecognized auth pattern: sshd_connection_closed_preauth |
| 16 | unrecognized auth pattern: sshd_timeout_or_disconnection |
