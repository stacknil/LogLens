# Security Policy

## Supported Versions

LogLens is a small public repository under active development.

| Version | Supported |
| ------- | --------- |
| main    | Yes       |
| older commits / snapshots | No |

At this stage, security fixes are applied to the `main` branch only.
Historical commits, experimental branches, and stale forks should be treated as unsupported.

## Reporting a Vulnerability

Please do **not** open a public issue for undisclosed security vulnerabilities.

Use GitHub's **private vulnerability reporting** feature for this repository if it is enabled.
If private reporting is unavailable for any reason, contact the maintainer through a private channel listed in the repository profile or repository documentation.

When reporting, please include:

- a clear description of the issue
- affected files, workflows, or code paths
- reproduction steps or a minimal proof of concept
- impact assessment
- any suggested remediation, if available

## Scope

This repository is a defensive log-analysis CLI for Linux authentication logs.

Relevant security reports may include, for example:

- unsafe workflow behavior
- supply-chain risks in CI or repository automation
- unsafe parsing behavior that could cause security-relevant misreporting
- vulnerabilities in repository-integrated tooling or update automation

Out of scope for vulnerability reports:

- feature requests
- parser support for additional benign log variants
- general false positives / false negatives that do not create a security vulnerability
- issues in third-party software outside this repository unless they directly affect this repository's shipped code or workflows

## Disclosure Expectations

Please allow time for triage and remediation before any public disclosure.

The maintainer will try to:

- acknowledge receipt of a report within a reasonable timeframe
- assess severity and impact
- coordinate remediation privately when appropriate
- disclose fixes responsibly after mitigation is available

## Notes

This repository is intended for defensive engineering and public-safe research.
Reports that seek offensive use beyond the repository's stated scope may be declined.
