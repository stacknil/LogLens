# One-Page Incident-Style Case: Concentrated SSH Failures

This compact evidence note follows one LogLens finding from raw log lines to a bounded conclusion. It uses the sanitized sample and its golden report fixture; it is incident-style in structure, not an incident verdict.

## Case Scope

| Field | Value |
| --- | --- |
| Evidence source | Linux `auth.log` / `secure` style syslog |
| Host | `example-host` |
| Review window | 2026-03-10 08:11:22 to 08:18:05 |
| Primary question | Did one source produce enough terminal SSH failures to meet the configured `brute_force` rule? |
| Parser mode | `syslog_legacy`, assumed year 2026 |

## 1. Raw Log

The selected evidence is five records from [`assets/sample_auth.log`](../assets/sample_auth.log):

```text
Mar 10 08:11:22 example-host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2
Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2
Mar 10 08:13:10 example-host sshd[1236]: Failed password for test from 203.0.113.10 port 51040 ssh2
Mar 10 08:14:44 example-host sshd[1237]: Failed password for guest from 203.0.113.10 port 51050 ssh2
Mar 10 08:18:05 example-host sshd[1238]: Failed password for invalid user deploy from 203.0.113.10 port 51060 ssh2
```

Observed facts: the records name one source address, five attempted usernames, and five failed SSH authentications over 6 minutes 43 seconds.

## 2. Normalized Events

LogLens converts the selected lines into typed events before rule evaluation:

| Evidence ID | Timestamp | Event type | Source IP | Username | Default signal role |
| --- | --- | --- | --- | --- | --- |
| `line:1` | 08:11:22 | `ssh_invalid_user` | `203.0.113.10` | `admin` | attempt evidence; terminal auth failure |
| `line:2` | 08:12:05 | `ssh_failed_password` | `203.0.113.10` | `root` | attempt evidence; terminal auth failure |
| `line:3` | 08:13:10 | `ssh_failed_password` | `203.0.113.10` | `test` | attempt evidence; terminal auth failure |
| `line:4` | 08:14:44 | `ssh_failed_password` | `203.0.113.10` | `guest` | attempt evidence; terminal auth failure |
| `line:5` | 08:18:05 | `ssh_invalid_user` | `203.0.113.10` | `deploy` | attempt evidence; terminal auth failure |

All five events carry the source-IP grouping key and the default `counts_as_terminal_auth_failure` signal required by `brute_force`. Unsupported raw lines do not receive that signal and cannot enter this count.

## 3. Finding

The detector selects the five-event window and emits this explainable finding in `report.json`:

```json
{
  "rule_id": "brute_force",
  "subject_kind": "source_ip",
  "subject": "203.0.113.10",
  "grouping_key": "source_ip",
  "threshold": 5,
  "observed_count": 5,
  "window_start": "2026-03-10 08:11:22",
  "window_end": "2026-03-10 08:18:05",
  "evidence_event_ids": ["line:1", "line:2", "line:3", "line:4", "line:5"],
  "verdict_boundary": "triage_signal_not_compromise_or_attribution"
}
```

Rule result: `observed_count` equals the configured threshold, so the evidence supports a `brute_force` triage finding for `203.0.113.10`. The same five events also support a separate `multi_user_probing` finding; this page follows only the primary brute-force evidence chain.

## 4. Bounded Conclusion

**Supported by the selected evidence:** one source address produced five normalized terminal SSH failures inside the configured 10-minute window. The threshold match is deterministic and traceable to five event IDs.

**Not established by the selected evidence:** that the source was malicious, that any credential succeeded, that `example-host` was compromised, or that an individual or organization can be attributed. The accepted login later in the sample comes from `203.0.113.20`, not the finding subject. Nearby sudo activity is not causally joined to this SSH cluster.

**Context required before disposition:** determine whether the source represents NAT, a bastion, an authorized internal scanner, a lab replay, a scheduled task with stale credentials, or shared-account use. The rule-specific corroboration questions are listed in [`false-positive-taxonomy.md`](./false-positive-taxonomy.md#brute-force).

**Parser boundary:** the full 16-line sample contains 14 parsed lines and 2 explicit parser warnings. Neither warning is part of `evidence_event_ids`. The warnings limit claims about evidence completeness, but they do not silently increase the finding count.

## Evidence Provenance

- Raw evidence: [`assets/sample_auth.log`](../assets/sample_auth.log)
- Golden finding: [`tests/fixtures/report_contracts/syslog_legacy/report.json`](../tests/fixtures/report_contracts/syslog_legacy/report.json)
- Full forensic explanation: [`case-study-linux-auth-bruteforce.md`](./case-study-linux-auth-bruteforce.md)
- Rule contract: [`rule-catalog.md`](./rule-catalog.md#brute-force)

Reproduce the report with:

```bash
./build/loglens --mode syslog --year 2026 ./assets/sample_auth.log ./out-incident-case
```
