# False-Positive Taxonomy

This document records benign or ambiguous contexts that can satisfy a LogLens rule threshold. A matching context does not erase the finding: it changes how a reviewer should interpret the normalized evidence and what external records are needed before disposition.

The taxonomy is not an allow-list, suppression policy, or incident verdict. LogLens reports the rule match, its evidence window, and its `verdict_boundary`; authorization, intent, compromise, and attribution remain outside the tool.

## Taxonomy Sources

| Source | Meaning in this catalog |
| --- | --- |
| NAT | Several clients are represented by one network address, weakening source-IP identity assumptions. |
| bastion | Administrative traffic is concentrated through an approved jump host or access gateway. |
| internal scanner | Authorized assessment, compliance, or account-audit tooling deliberately generates authentication activity. |
| lab replay | Training, test, demonstration, or pipeline validation data reproduces a finding-shaped sequence. |
| scheduled admin task | A recurring operational job produces repeated authentication failures or privileged commands. |
| shared account | Several operators or services use one account, weakening individual attribution and concentrating activity. |

`bastion` and `shared account` are separate hypotheses. A bastion explains host or network concentration; a shared account explains identity concentration. Either can exist without the other.

## Brute Force

Rule evidence: at least 5 terminal SSH failure signals grouped by `source_ip` within 10 minutes by default.

Verdict boundary: `triage_signal_not_compromise_or_attribution`.

| Source | Why the threshold can match | Evidence that supports the explanation | Residual uncertainty |
| --- | --- | --- | --- |
| NAT | Independent users or services behind one egress address contribute failures to the same `source_ip` group. | VPN, proxy, firewall, or DHCP records map the source address and window to multiple internal clients. | Aggregation can explain volume but does not establish that every attempt was authorized. |
| bastion | Multiple administrators or automation jobs originate from one approved jump host. | Bastion inventory, session audit records, and operator mappings cover the finding window and evidence event IDs. | An approved bastion can still carry stale credentials, misuse, or a compromised session. |
| internal scanner | An authorized scanner tests SSH exposure or credential controls and produces terminal failures by design. | Scanner ownership, target scope, source-address inventory, and a matching scan schedule or change record. | Scanner identity supports authorization but does not validate target scope or configuration. |
| lab replay | A fixture, demonstration, or validation job replays a concentrated failure sequence. | Ingestion provenance, replay job logs, fixture hashes, or known synthetic timestamps match the evidence. | Replayed data in a production evidence path is still a provenance or pipeline-quality issue. |
| scheduled admin task | A recurring job repeatedly uses an expired, rotated, or mistyped credential. | Scheduler logs, service ownership, credential-rotation history, and matching execution timestamps. | A job explanation does not prove the credential failures are harmless or properly contained. |
| shared account | Several operators or services retry the same shared credential from one source. | Account ownership records, approved-use policy, bastion or session logs, and change-window context. | The shared identity prevents reliable attribution to an individual operator. |

## Multi-User Probing

Rule evidence: at least 3 distinct usernames in attempt-evidence signals grouped by `source_ip` within 15 minutes by default.

Verdict boundary: `triage_signal_not_intent_or_attribution`.

| Source | Why the threshold can match | Evidence that supports the explanation | Residual uncertainty |
| --- | --- | --- | --- |
| NAT | Separate legitimate users behind one egress address attempt their own usernames during the same window. | Network translation, VPN, proxy, or DHCP records map the grouped address to distinct clients and expected users. | NAT explains source aggregation but not whether every attempted username was expected. |
| bastion | An access gateway handles sessions for several named administrators or service accounts. | Bastion session records map each attempted username and timestamp to approved operators or workflows. | Missing session attribution leaves the username spread unexplained. |
| internal scanner | Account-audit or exposure tooling tries a configured username set to validate controls. | Scanner configuration, approved account list, target scope, and execution schedule match the finding. | A broad or outdated username list may still represent a control or scope problem. |
| lab replay | Synthetic data preserves username diversity to exercise parser or detector behavior. | Fixture provenance, replay logs, and expected username lists match the evidence event IDs. | Synthetic data must still be separated from operational evidence before conclusions are drawn. |
| scheduled admin task | Migration, monitoring, or account-validation automation cycles through several service identities. | Job definition, account inventory, owner confirmation, and scheduler timestamps match the rule window. | Unexpected usernames or executions outside the approved window remain unexplained. |
| shared account | Operators or tooling fall back across several shared or service accounts from one source. | Account-use policy, workflow configuration, and session logs explain the full observed username set. | One shared account alone does not create distinct-username spread; the explanation requires evidence of multiple accounts being tried. |

## Sudo Burst

Rule evidence: at least 3 `sudo_command` signals grouped by `username` within 5 minutes by default.

Verdict boundary: `triage_signal_not_maliciousness_or_authorization`.

| Source | Why the threshold can match | Evidence that supports the explanation | Residual uncertainty |
| --- | --- | --- | --- |
| NAT | NAT does not directly increase this username-grouped rule, but it can confuse attempts to correlate the finding with nearby source-IP findings. | Session records and host-local audit context link the sudo commands to a specific login independently of the network address. | Without session linkage, network proximity is not evidence that SSH and sudo findings share an actor. |
| bastion | An approved administrator reaches the host through a jump path and executes several maintenance commands quickly. | Bastion session records, target-host login records, and a change ticket align with the sudo evidence window. | A valid access path does not establish that each command was authorized. |
| internal scanner | Compliance, inventory, or endpoint assessment tooling executes a short privileged command sequence. | Agent identity, scanner policy, command allow-list, and execution logs match the reported commands and timestamps. | Unexpected commands or host scope remain reviewable even when the tool is authorized. |
| lab replay | Demonstration or test evidence contains a compact sudo sequence. | Dataset provenance, replay job records, and known synthetic account or host values match the finding. | Replayed privileged activity mixed into operational logs still weakens evidence provenance. |
| scheduled admin task | Package updates, service repair, backup, or maintenance automation runs several sudo commands in one window. | Scheduler records, automation definitions, change windows, and command text match the evidence event IDs. | Execution outside schedule or divergence from the expected command set remains unexplained. |
| shared account | Several administrators use one account, or automation and humans share the same identity, concentrating commands under one `username`. | Session attribution, privileged access management records, operator rosters, and command ownership cover the complete window. | The account model prevents reliable individual attribution and may itself be a control weakness. |

## Cross-Rule Interpretation

- A `brute_force` and `multi_user_probing` finding over the same source and window are two views of overlapping evidence, not automatically two independent actors or incidents.
- A nearby `sudo_burst` finding is not causally linked to an SSH finding unless external session evidence establishes that relationship.
- `evidence_event_ids`, `window_start`, and `window_end` define exactly what LogLens counted. Review those records before applying contextual explanations.
- Parser warnings and unsupported lines describe evidence completeness. They do not count toward findings, but a high unsupported-line rate weakens claims that an activity is absent.

## Evidence Integrity Boundary

Duplicate recognized lines, replayed collections, or merged log exports can inflate a rule count even when every line parses successfully. That is an evidence-provenance question, distinct from unsupported parser warnings. Review ingestion history and source hashes when replay or duplication is plausible.

The appropriate conclusion is therefore bounded: a taxonomy source may explain why a threshold was met, but only corroborating records can support a benign disposition. LogLens does not make that disposition automatically.
