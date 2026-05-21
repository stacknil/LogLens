# LogLens Report

## Summary

- Input: `tests/fixtures/report_contracts/multi_host_journalctl_short_full/input.log`
- Input mode: journalctl_short_full
- Timezone present: true
- Total lines: 15
- Parsed lines: 12
- Unparsed lines: 3
- Parse success rate: 80.00%
- Parsed events: 12
- Findings: 3
- Parser warnings: 3

## Host Summary

| Host | Parsed Events | Findings | Warnings |
| --- | ---: | ---: | ---: |
| alpha-host | 7 | 2 | 1 |
| beta-host | 5 | 1 | 2 |

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
| sshd_connection_closed_preauth | 1 |
| sshd_timeout_or_disconnection | 1 |

## Parser Warnings

| Line | Reason |
| ---: | --- |
| 12 | unrecognized auth pattern: pam_sss_unknown_user |
| 14 | unrecognized auth pattern: sshd_connection_closed_preauth |
| 15 | unrecognized auth pattern: sshd_timeout_or_disconnection |
