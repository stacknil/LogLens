# Roadmap

LogLens is in a narrow reviewer-stable phase. The near-term focus is to
stabilize parser evidence, tests, documentation boundaries, and release
artifacts rather than expand the project surface.

## External Review Surface

Open review issues should stay concrete enough to reproduce from checked-in
fixtures. A good issue names the exact sample input, the expected event or
warning output, and the acceptance criteria for a bounded change or review.

The current public review entry is intentionally small: trace one
`pam_unix_session_closed` line through parser-coverage telemetry and confirm
that unsupported auth evidence remains visible without becoming detector
evidence.

Pinned regression (issue #83): `assets/mixed_auth_corpus.log` line 11
(`pam_unix(sshd:session): session closed for user user001`) is confirmed as
parser telemetry only — `unsupported_pam_variant` /
`unrecognized auth pattern: pam_unix_session_closed` in
`assets/mixed_auth_parser_coverage.json`, with no parsed event and no detector
finding. Covered by
`test_mixed_auth_first_pam_unix_session_closed_is_unsupported_telemetry`.

## Parked Directions

- Add parser coverage only when a sanitized fixture line and deterministic
  expected event or warning bucket are known up front.
- Keep clean-clone reproduction feedback tied to exact failing commands or
  documentation mismatches.
- Grow the noisy auth corpus only when a proposed batch answers a new parser
  uncertainty question not already covered by `assets/mixed_auth_corpus.log`.
- Keep additional PAM or SSH variants scoped to defensive Linux authentication
  evidence; no live logs, real identifiers, credentials, or platform-coverage
  claims.
