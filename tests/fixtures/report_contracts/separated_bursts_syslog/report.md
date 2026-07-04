# LogLens Report

## Summary

- Input: `tests/fixtures/report_contracts/separated_bursts_syslog/input.log`
- Input mode: syslog_legacy
- Assume year: 2026
- Timezone present: false
- Total input lines: 10
- Total lines: 10
- Skipped blank lines: 0
- Parsed lines: 10
- Unparsed lines: 0
- Parse success rate: 100.00%
- Parsed events: 10
- Findings: 2
- Parser warnings: 0

## Findings

| Rule | Subject | Count | Window | Notes |
| --- | --- | ---: | --- | --- |
| brute_force | 203.0.113.40 | 5 | 2026-03-10 09:00:00 -> 2026-03-10 09:04:00 | 5 failed SSH attempts from 203.0.113.40 within 10 minutes. |
| brute_force | 203.0.113.40 | 5 | 2026-03-10 15:00:00 -> 2026-03-10 15:04:00 | 5 failed SSH attempts from 203.0.113.40 within 10 minutes. |

## Event Counts

| Event Type | Count |
| --- | ---: |
| ssh_failed_password | 10 |

## Parser Quality

All analyzed lines matched a supported pattern.

No parser failure categories were recorded.

## Parser Warnings

No malformed lines were skipped.
