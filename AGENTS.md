# AGENTS.md

## Project
LogLens is a defensive C++20 CLI for parsing Linux authentication logs and generating structured detection reports.

## Priorities
1. Working MVP first
2. Clean modular C++20
3. Safe public-repo content
4. Reproducible build and tests
5. Clear README and docs

## Constraints
- Do not add offensive or exploitation functionality
- Do not use real IPs, secrets, usernames, or private infrastructure identifiers
- Prefer standard library over third-party dependencies
- Keep file structure simple
- Avoid unnecessary templates or meta-programming
- Avoid heavy regex-only designs if a clearer parser is possible
- Keep detection rules centralized and configurable

## Code style
- C++20
- Readable names
- Small functions
- Comments only where they add real value
- Fail gracefully on malformed log lines

## Repository rules
- Always update README when adding user-visible features
- Add or update tests for parser and detector changes
- Preserve public-safe placeholders like 203.0.113.x and example-host
- Do not introduce large unrelated refactors

## Task behavior
When given a task:
1. inspect repository state
2. explain plan briefly
3. implement in small steps
4. run build/tests if available
5. summarize created/modified files and remaining issues
