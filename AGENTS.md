# AGENTS.md

## LogLens Repo Rules

- Keep the repository defensive and public-safe. Do not add offensive, exploitation, persistence, or live attack functionality.
- Use only safe placeholders such as `203.0.113.x` and `example-host`. Never add real IPs, usernames, secrets, or private identifiers.
- Prefer standard C++20 and the standard library. Keep code modular, readable, and easy to extend.
- Keep detection rules centralized and configurable. Avoid large unrelated refactors.
- Fail gracefully on malformed log lines.
- Update README or docs for user-visible changes.
- Tests are required for code changes. Add or update parser/detector tests and run available build/tests when possible:
  `cmake -S . -B build`
  `cmake --build build`
  `ctest --test-dir build --output-on-failure`
