# Linux Auth Brute-Force Case Study

This case study explains how LogLens interprets a sanitized Linux authentication sample as evidence. The emphasis is forensic reasoning: what the records support, what they do not support, and where parser uncertainty remains visible.

## Scenario

The evidence set is a 16-line `auth.log` / `secure` style excerpt from `example-host`. It contains a concentrated SSH failure sequence, later privileged command activity by `alice`, one accepted SSH login, one PAM authentication failure, and two preauth connection/noise records that LogLens does not normalize into typed events.

The central question is evidentiary, not operational:

Does this record support triage findings for SSH brute force, multi-user probing, and bursty sudo activity while preserving parser uncertainty as explicit warnings?

The answer is yes for triage. The answer is no for compromise determination, attribution, or response action.

## Raw evidence

The strongest sequence is five SSH failures from the same source IP in less than seven minutes:

```text
Mar 10 08:11:22 example-host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2
Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2
Mar 10 08:13:10 example-host sshd[1236]: Failed password for test from 203.0.113.10 port 51040 ssh2
Mar 10 08:14:44 example-host sshd[1237]: Failed password for guest from 203.0.113.10 port 51050 ssh2
Mar 10 08:18:05 example-host sshd[1238]: Failed password for invalid user deploy from 203.0.113.10 port 51060 ssh2
```

This sequence carries two separate evidentiary signals: repeated terminal SSH failures and username spread. The usernames `admin`, `root`, `test`, `guest`, and `deploy` are not treated as proof of intent, but they are sufficient to support a username-probing triage signal.

The later context is qualitatively different:

```text
Mar 10 08:20:10 example-host sshd[1240]: Accepted password for alice from 203.0.113.20 port 51111 ssh2
Mar 10 08:21:00 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh
Mar 10 08:22:10 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/journalctl -xe
Mar 10 08:24:15 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/vi /etc/ssh/sshd_config
```

The accepted login and sudo activity do not prove that the earlier SSH failures succeeded. They establish temporal context and a separate burst of privileged commands by `alice`.

Two records remain parser-visible but non-normalized:

```text
Mar 10 08:30:12 example-host sshd[1244]: Connection closed by authenticating user alice 203.0.113.50 port 51290 [preauth]
Mar 10 08:31:18 example-host sshd[1245]: Timeout, client not responding from 203.0.113.51 port 51291
```

Their value is negative evidence about parser scope: LogLens saw them, bucketed them, and did not silently use them as detection evidence.

## Normalization model

LogLens first converts recognized records into typed events. Detection rules consume those normalized events, not raw strings.

| Raw evidence class | Normalized event | Evidentiary use |
| --- | --- | --- |
| `Failed password for invalid user ...` | `ssh_invalid_user` | terminal SSH failure and attempted username evidence |
| `Failed password for root/test/guest ...` | `ssh_failed_password` | terminal SSH failure evidence |
| `Invalid user backup ...` | `ssh_invalid_user` | attempted username evidence from a separate source IP |
| `Failed publickey for invalid user svc-backup ...` | `ssh_failed_publickey` | SSH failure evidence from a separate source IP |
| `pam_unix(sshd:auth): authentication failure ...` | `pam_auth_failure` | lower-confidence attempt evidence by default |
| `sudo: alice : ... COMMAND=...` | `sudo_command` | sudo burst evidence for user `alice` |
| `Accepted password for alice ...` | `ssh_accepted_password` | context only; not failure evidence |

This model is intentionally conservative. It separates parser recognition from detector meaning. A parsed event can be context, lower-confidence attempt evidence, terminal failure evidence, or sudo burst evidence depending on the configured signal mapping.

## Detection rules

The rules act as evidence filters:

| Rule | Evidence threshold | Case-study match |
| --- | --- | --- |
| `brute_force` | at least 5 terminal SSH failures from one source IP within 10 minutes | `203.0.113.10` has 5 qualifying failures from `08:11:22` to `08:18:05` |
| `multi_user_probing` | at least 3 attempted usernames from one source IP within 15 minutes | `203.0.113.10` touches 5 usernames: `admin`, `deploy`, `guest`, `root`, `test` |
| `sudo_burst` | at least 3 sudo commands by one user within 5 minutes | `alice` has 3 sudo commands from `08:21:00` to `08:24:15` |

`pam_auth_failure` is intentionally lower-confidence by default. It is preserved in the event counts but does not become terminal brute-force evidence unless the configuration explicitly upgrades it.

## Parser coverage

The report's parser quality section is part of the evidence, not an implementation detail:

| Metric | Value |
| --- | ---: |
| total input lines | 16 |
| analyzed lines | 16 |
| skipped blank lines | 0 |
| parsed lines | 14 |
| unparsed lines | 2 |
| parse success rate | 87.50% |
| parser warnings | 2 |

The coverage numbers describe the reliability envelope of the findings. The findings are based on the 14 normalized lines. The 2 unsupported lines are not hidden and are not used as detector input.

> Parser observability > silent detection claims.

## Findings

The evidence supports three triage findings:

| Finding | Evidence basis | Interpretation |
| --- | --- | --- |
| `brute_force` on `203.0.113.10` | five terminal SSH failures in a 10-minute window | a concentrated failure pattern from one source IP |
| `multi_user_probing` on `203.0.113.10` | five usernames in the same window | username spread consistent with probing |
| `sudo_burst` on `alice` | three sudo commands in under five minutes | concentrated privileged command activity |

The first two findings share the same source IP and time window. That strengthens the triage value because frequency and username spread point to the same cluster. It still does not establish compromise.

The sudo finding is adjacent but separate. It is not joined to the SSH failure cluster by LogLens because the tool does not infer session causality or cross-source relationships.

## Warnings / unknown patterns

The parser warnings are:

| Line | Failure category | Unknown-pattern bucket | Evidence interpretation |
| ---: | --- | --- | --- |
| 15 | `known_program_unknown_message` | `sshd_connection_closed_preauth` | preauth connection-close noise was observed but not promoted to a typed event |
| 16 | `known_program_unknown_message` | `sshd_timeout_or_disconnection` | timeout/disconnection noise was observed but not promoted to a typed event |

These warnings are useful because they prevent silent overconfidence. A reviewer can see both the finding-producing evidence and the unsupported surrounding records.

## False-positive boundary

The findings should be read as triage statements and checked against the rule-by-rule taxonomy in [`rule-catalog.md`](./rule-catalog.md):

- `203.0.113.10` is a documentation-range placeholder; in a real case, the same pattern could be an external scanner, shared gateway, internal test, or replayed lab traffic.
- Username spread supports a probing interpretation, but intent is not observable from these lines alone.
- The accepted login for `alice` comes from `203.0.113.20`, not from the brute-force source IP in this sample.
- The sudo burst is temporally close to the accepted login, but LogLens does not assert that the login caused the sudo activity.
- The PAM failure for `alice` is parsed, but its default signal role is lower-confidence attempt evidence.
- The two unknown-pattern warnings are explicitly excluded from detector evidence.

The boundary is deliberate: LogLens can say "these records meet these rule thresholds." It cannot say "this host was compromised."

## Reproduction command

The evidence artifacts referenced by this case study are reproducible with:

```bash
./build/loglens --mode syslog --year 2026 --csv ./assets/sample_auth.log ./out-case-study
```

For MSVC Debug builds, the executable path may be:

```bash
./build/Debug/loglens.exe --mode syslog --year 2026 --csv ./assets/sample_auth.log ./out-case-study
```

The checked-in report-contract fixture for the same evidence shape is [`tests/fixtures/report_contracts/syslog_legacy`](../tests/fixtures/report_contracts/syslog_legacy).

## What the tool does not decide

LogLens does not decide:

- whether `example-host` was compromised
- whether any credential was guessed successfully
- whether `alice`'s sudo activity was legitimate administration
- whether a source IP is malicious infrastructure
- whether these records belong to a broader campaign
- whether unsupported parser buckets are benign or malicious
- whether multiple hosts should be correlated
- what containment, eradication, or recovery action should follow

The tool's role is to preserve the evidence path: raw line, normalized event, signal boundary, finding, parser warning, and non-goal.
