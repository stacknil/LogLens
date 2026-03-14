# LogLens MVP Design

LogLens is intentionally split into three small layers:

1. `parser`
   Reads `auth.log` or `secure` style lines, builds normalized `Event` values, and records malformed-line warnings without aborting the run.
2. `detector`
   Applies centralized threshold rules to parsed events and emits stable `Finding` records.
3. `report`
   Converts findings and event summaries into deterministic Markdown and JSON output files.

The CLI in `src/main.cpp` wires those layers together:

- parse a file
- analyze the normalized events
- write `report.md` and `report.json`

This keeps the MVP easy to test and extend without introducing heavy dependencies or unnecessary abstractions.
