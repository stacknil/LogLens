# Repository Hardening

## Expected PR Checks

Every pull request to `main` should pass these checks before merge:

- `CI (ubuntu-latest)`
- `CI (windows-latest)`
- `CodeQL`

CI validates that the repository builds and tests cleanly on both supported GitHub-hosted platforms. CodeQL provides GitHub code scanning for the C++ codebase using a minimal workflow with an explicit CMake build.

## Merge Protection

For the `main` branch, enable branch protection or a ruleset that requires:

- pull requests before merge
- all required status checks to pass
- the three checks above as required checks

This repository is intended to stay portfolio-safe and reproducible, so merges to `main` should not bypass failing automation.

## Workflow Supply Chain

The GitHub Actions workflows pin third-party actions to full commit SHAs rather than floating major tags. This reduces the chance of an unexpected upstream action change altering repository behavior without review.

When updating a pinned action:

1. choose the target release from the official action repository
2. replace the full SHA in the workflow
3. keep the inline version comment in sync
4. verify CI and CodeQL still run cleanly
