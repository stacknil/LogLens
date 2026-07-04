# How LogLens Treats Parser Uncertainty as Evidence

A log analysis tool can appear more certain than it is when unsupported input
quietly disappears. LogLens takes the opposite approach: parser uncertainty is
part of the review artifact.

The practical review question is simple: when a report contains no finding,
did the relevant activity fail to meet a rule, or did the parser fail to
understand the source line? The report should preserve enough evidence to tell
those cases apart.

## Three visible line outcomes

The [parser contract](parser-contract.md) gives every input line one of three
outcomes:

1. A recognized authentication line becomes a typed event.
2. A blank line is counted in `skipped_blank_lines`.
3. A malformed or unsupported line becomes a parser warning with a line
   number, failure category, and unknown-pattern bucket.

Unsupported lines do not become detector input. They remain visible as
coverage telemetry. This keeps a parser gap from being mistaken for negative
security evidence.

The categories are deliberately coarser than the pattern buckets. For example,
an unsupported `sshd` pre-authentication close and an unsupported negotiation
failure can both belong to `known_program_unknown_message` while retaining
different buckets. The category supports summary review; the bucket preserves
the narrower engineering question.

## A noisy corpus is useful evidence

The checked-in
[`mixed_auth_corpus.log`](../assets/mixed_auth_corpus.log) is a sanitized,
150-line syslog-style fixture. Its paired
[`mixed_auth_parser_coverage.json`](../assets/mixed_auth_parser_coverage.json)
records recognized events, warnings, blank lines, failure categories, pattern
buckets, and source-line references.

The corpus is intentionally noisy. A lower parse-success rate is not hidden or
reframed as a quality claim. What matters is that the unsupported portion has a
stable, inspectable shape. The locked expectations are documented in
[parser coverage notes](parser-coverage-notes.md) and exercised by parser and
report-contract tests.

## Parsing and detection remain separate

A parsed event is not automatically a detection signal. LogLens keeps that
boundary explicit through its signal configuration. Supported success and
audit events can remain reportable context without contributing to a
brute-force finding. Unsupported lines never cross that boundary.

This separation lets a reviewer ask two different questions:

- Did the parser classify this line as documented?
- Did the configured rule use that event as evidence?

The [parser conformance matrix](parser-conformance-matrix.md) and
[rule catalog](rule-catalog.md) provide the corresponding review surfaces.

## Reproduce the contract

From the repository root:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

For a shorter artifact-first route, use the
[reviewer path](reviewer-path.md). A useful external review can stay narrow:
check one supported line, one unsupported line, or one report warning against
the documented outcome.

## What this does not prove

Visible uncertainty is not complete parser coverage. LogLens does not claim to
support every Linux distribution, authentication module, or message variant.
It also does not turn a rule match into a compromise verdict, attribution, or
blocking recommendation. The case study shows how uncertainty is preserved for
review, not how uncertainty is eliminated.
