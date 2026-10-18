# Reliability audit: syslog day conversion

Date: 2026-10-15. Baseline: `e2937e8`. Local branch:
`reliability/syslog-day-boundaries`. Decision: **ACCEPT**, completion criterion A.
This is a bounded source review and executed regression, not a complete security audit.

## Inventory and contracts

- C++20, extensions disabled; CMake >= 3.20, CTest, standard-library parser.
- Six baseline C++ test executables cover parsing, generated properties,
  detectors, reports, CLI, and report contracts. An optional seventh CTest entry
  runs the Python episode-candidate research tests.
- CLI input reaches `AuthLogParser::parse_file`, then `parse_stream` (`getline`),
  then `parse_line`. Internal stages are timestamp/hostname, source envelope,
  source-IP classification, program dispatch, and handler normalization.
- Configuration uses its own JSON cursor; CLI year conversion and parser integer
  conversion use `from_chars`. CLI/config years are restricted to 1000..9999.
- `parse_line` returns an optional owning `Event`, resetting caller-supplied
  diagnostics before parsing. Temporary `string_view` tokens borrow input;
  event strings own their data. `parse_stream` accumulates events and warnings.
  `parse_file` throws on open failure. Allocation failure/resource exhaustion
  is not converted into a per-line warning. Stream I/O failure is a separate,
  untested boundary in this increment.
- Existing deterministic properties include 512 arbitrary-byte inputs in both
  modes, malformed IPv4 tokens, telemetry stability, and handler permutations.
- Existing `fuzz/parser_fuzz.cpp` invokes both modes with seven corpus seeds.
  CMake instruments the fuzz library and driver with ASan/UBSan/libFuzzer.
  CI defines a 2,000-run, 1,024-byte fuzz smoke job, Linux/Windows CTest jobs,
  and C++ CodeQL analysis. These are configuration observations, not claims of
  a newly executed remote CI campaign.
- `docs/adr/0001-episode-semantics-boundaries.md` keeps research candidate
  algorithms distinct from production detection. No research fixtures, results,
  candidate algorithms, finding identities, signal defaults, or report schema
  are edited. Paper A1 is entirely excluded.

## Candidate assessment

Likelihood below means plausibility from inspected code, not measured prevalence.
Only the selected target received new experimental coverage.

| Surface | Likelihood | Potential impact | Reproducibility / testability | Decision |
| --- | --- | --- | --- | --- |
| Truncated/malformed auth lines | Common input; defect unconfirmed | Lost events or wrong warning | High; existing fixtures and byte properties | Defer broader prefix corpus |
| Encoding and embedded NUL | Plausible input; defect unconfirmed | Token confusion or output ambiguity | High; length-aware views and unsigned-char ctype casts inspected | Only day-token NUL/high-byte controls added |
| Oversized input | Plausible; no explicit getline/retention cap | Memory pressure from long lines or accumulated results | High for bounded cases; resource policy unspecified | Defer; one 4,096-digit day tested |
| Numeric conversion/narrowing | Confirmed for day conversion | Invalid input can emit an event on an incorrect date | Minimal `Mar 257` witness; deterministic oracle | **Select** |
| Lifetime/ownership | Low source-level signal; not cleared | Potential memory corruption if borrowing escapes | ASan feasible; events own strings | Run sanitizers, no separate lifetime redesign |
| Invalid timestamps | Confirmed day subcase; other cases unconfirmed | Evidence chronology and downstream counts | Independent month lengths and leap-year controls | Same selected conversion boundary |
| Sequential events | Parser config is immutable across calls; detector state is more complex | Recovery/accounting or grouping errors | Three-line parser recovery is deterministic | Verify recovery; leave detector method frozen |

## Confirmed defect and smallest fix

`build_timestamp` constructed `chrono::day` from an unchecked `int` and only
then called `year_month_day::ok()`. The tested libstdc++ representation narrows
the day before validation. A syntactically valid integer outside the day domain
can therefore become a valid date. The baseline accepted the `257` witness;
the new test failed immediately. No sanitizer diagnostic was necessary to
detect this semantic error, and no memory-corruption vulnerability is claimed.

The fix rejects values outside 1..31 before calendar construction. Existing
month/leap validation and error taxonomy remain in use. Valid-input detection
semantics are unchanged; previously accepted invalid day tokens now become
warnings and can no longer contribute events. Consumers that relied on this
invalid-input acceptance will observe different counts.

## Decision evidence and limits

- Rejected: relying only on ASan/UBSan. Defined narrowing can still violate a
  semantic input contract; a domain oracle is required.
- Rejected: normalizing or clamping invalid days. That invents evidence dates.
- Rejected: changing all integer parsing or adding a global line-size policy.
  Neither is needed for the demonstrated day defect.
- No goldens were updated. Existing report, CLI, detector, and research tests
  pass without fixture changes; exact commands and results are in
  [the execution report](FUZZING-OR-BOUNDARY-TEST-REPORT.md).
- This run covers Linux/GCC and Clang with libstdc++; Windows/MSVC and other standard libraries
  were not executed locally. Finite clean sanitizer runs do not prove complete
  memory safety or rule out other timestamp defects. Direct API year ranges,
  timezone/clock lexical policy, and resource limits remain outside scope.
- Rollback: revert this increment; doing so restores invalid-day acceptance.
  No data migration or research-artifact regeneration is involved.
- Suggested next increment: deterministic truncation tests around the source
  envelope/program delimiter, including owning-event lifetime checks. Do not
  implement automatically or expand the supported grammar.
