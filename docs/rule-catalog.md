# Rule Catalog

The rule catalog documents how LogLens turns normalized authentication events into triage findings. It is intended for reviewers who want to inspect rule logic without reading the C++ implementation first.

The rule catalog is Sigma-informed but not a Sigma-compatible export format.

Sigma's `detection`, `logsource`, and `metadata` framing is useful as a mental model: define what the rule looks for, name the evidence source, and keep rule boundaries explicit. LogLens keeps a narrower local format because its rules operate on normalized `Event` and `AuthSignal` objects, not on arbitrary backend query syntax.

## Catalog Scope

Logsource equivalent:

- Linux authentication evidence parsed by LogLens from `syslog_legacy` input, such as `auth.log` or `secure`
- Linux authentication evidence parsed by LogLens from `journalctl_short_full` input, such as `journalctl --output=short-full`

Detection equivalent:

- Rule logic runs after parser normalization and signal mapping.
- Unsupported parser warnings do not become rule input.
- Parsed events only become rule input when the signal mapping marks them as relevant evidence for that rule family.

Metadata equivalent:

- Rule names are stable report values.
- Windows and thresholds are configurable through `config.json`.
- Default values below match the built-in detector configuration.
- The checked-in `assets/sample_config.json` is a tested default-equivalent fixture.

## Brute Force

### Rule name

`brute_force`

### Input event types

Default terminal SSH failure evidence:

- `ssh_failed_password`
- `ssh_invalid_user`
- `ssh_failed_publickey`
- `ssh_failed_keyboard_interactive`
- `ssh_max_auth_tries`

`pam_auth_failure` is not terminal SSH failure evidence by default. It can be configured differently through `auth_signal_mappings`, but the built-in default keeps it lower-confidence.

### Grouping key

`source_ip`

Signals without a source IP are not grouped for this rule.

### Window

10 minutes by default.

The detector uses a sliding timestamp window within each source-IP group.

### Threshold

5 terminal SSH failure signals by default.

### Output subject

`subject_kind`: `source_ip`

`subject`: the source IP that met the threshold

### False-positive boundary

This rule identifies concentrated failed SSH authentication evidence from one source IP. It does not decide whether the source is malicious, shared infrastructure, a vulnerability scanner, an internal test, a NAT gateway, or replayed lab traffic.

The finding is a triage signal. It is not a compromise verdict, attribution claim, or recommendation to block an address.

### Why unsupported evidence is not counted

Unsupported lines are parser warnings, not `AuthSignal` records. They may appear in `top_unknown_patterns`, but they do not carry the `counts_as_terminal_auth_failure` flag required by this rule.

This prevents unsupported preauth noise, malformed lines, and unmodeled auth-family messages from silently increasing brute-force counts.

## Multi-User Probing

### Rule name

`multi_user_probing`

### Input event types

Default attempt evidence:

- `ssh_failed_password`
- `ssh_invalid_user`
- `ssh_failed_publickey`
- `ssh_failed_keyboard_interactive`
- `ssh_max_auth_tries`
- `pam_auth_failure`

The rule uses signal mapping, not raw event names directly. By default, `pam_auth_failure` counts as attempt evidence but not terminal SSH failure evidence.

### Grouping key

`source_ip`

Signals without a source IP are not grouped for this rule. Distinct username counting only uses signals that carry a non-empty username.

### Window

15 minutes by default.

The detector uses a sliding timestamp window within each source-IP group.

### Threshold

3 distinct usernames by default.

The reported event count is the number of attempt-evidence signals in the selected window. The rule fires when the distinct username count reaches the threshold.

### Output subject

`subject_kind`: `source_ip`

`subject`: the source IP that targeted multiple usernames

The finding also reports the username set observed in the selected window.

### False-positive boundary

This rule identifies username spread from one source IP. Username spread can be consistent with probing, but it can also appear in administrative testing, shared bastion traffic, noisy monitoring, or replayed sample data.

The rule does not infer intent. It only states that one source IP produced attempt evidence against multiple usernames inside the configured window.

### Why unsupported evidence is not counted

Unsupported records do not provide normalized usernames, source IPs, or attempt-evidence flags. Counting them would turn parser uncertainty into detector confidence.

Keeping them in parser warnings preserves evidence visibility without allowing unknown log patterns to inflate username-probing findings.

## Sudo Burst

### Rule name

`sudo_burst`

### Input event types

Default sudo burst evidence:

- `sudo_command`

Other sudo-adjacent or session events are not counted by default, including:

- `sudo_auth_failure`
- `sudo_policy_denied`
- `session_opened`

### Grouping key

`username`

Signals without a username are not grouped for this rule.

### Window

5 minutes by default.

The detector uses a sliding timestamp window within each username group.

### Threshold

3 sudo command signals by default.

### Output subject

`subject_kind`: `username`

`subject`: the user who met the sudo burst threshold

### False-positive boundary

This rule identifies concentrated sudo command activity by one user. It does not decide whether the activity is malicious, authorized maintenance, incident response, package management, service repair, or a scripted administrative task.

The finding is strongest when reviewed with session context, change windows, host ownership, and the command text preserved in the report.

### Why unsupported evidence is not counted

Unsupported sudo-like lines are parser warnings, not sudo burst signals. They do not carry `counts_as_sudo_burst_evidence`.

This prevents malformed or unmodeled privilege-related records from becoming silent evidence for privileged activity bursts.

## Rule Boundary Summary

| Rule | Default grouping key | Default window | Default threshold | Output subject |
| --- | --- | ---: | ---: | --- |
| `brute_force` | `source_ip` | 10 minutes | 5 terminal SSH failures | `source_ip` |
| `multi_user_probing` | `source_ip` | 15 minutes | 3 distinct usernames | `source_ip` |
| `sudo_burst` | `username` | 5 minutes | 3 sudo commands | `username` |

LogLens findings are deterministic rule outputs over normalized evidence. They are not incident verdicts. Parser coverage, warning buckets, and unsupported patterns remain visible so reviewers can see what the detector did not count.
