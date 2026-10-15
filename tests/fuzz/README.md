# Parser fuzz harness

For the focused day-token oracle, build the optional `fuzz_timestamp_day`
target using the same configuration. Its three seeds are in
`tests/fuzz/corpus/timestamp_day`; copy them into a writable build-directory
corpus before running. See [the executed boundary/fuzz report](../../FUZZING-OR-BOUNDARY-TEST-REPORT.md)
for exact commands, the confirmed day-narrowing regression, and coverage limits.

The parser fuzz target is optional and requires Clang with libFuzzer support.
It exercises both supported input modes and treats these result invariants as
crash conditions:

- every emitted event has a normalized event type and non-empty program
- every rejected line has a non-empty parser failure reason
- arbitrary input must not terminate the parser unexpectedly

Configure and run a bounded local campaign:

```bash
CC=clang CXX=clang++ cmake -S . -B build-fuzz \
  -D CMAKE_BUILD_TYPE=RelWithDebInfo \
  -D BUILD_TESTING=OFF \
  -D LOGLENS_BUILD_FUZZERS=ON
cmake --build build-fuzz --target fuzz_parser
./build-fuzz/fuzz_parser -runs=2000 -max_len=1024 tests/fuzz/corpus/parser
```

The checked-in corpus is sanitized and intentionally small. CI uses it only as
a bounded smoke campaign; longer local campaigns can reuse the same target.
