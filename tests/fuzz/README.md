# Parser fuzz harness

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
