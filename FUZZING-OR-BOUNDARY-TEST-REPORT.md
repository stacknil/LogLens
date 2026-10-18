# Executed boundary test report

Date: 2026-10-15. Scope: syslog integer day to calendar conversion only.
Result: **ACCEPT — confirmed defect with failing regression and validated fix**.

## Environment

Linux under WSL; GCC/G++ 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), libstdc++,
CMake 3.28.3, Ninja 1.11.1, Python 3.12.3, jsonschema 4.10.3. Clang/libFuzzer
was initially unavailable. With explicit user authorization, the distribution
packages `clang` and `libclang-rt-dev` were installed, providing Ubuntu Clang
18.1.3 and compiler-rt/libFuzzer 18. The existing general parser fuzz harness
and CI smoke configuration are unchanged; a focused day-token target is added.

## Corpus and oracle

`tests/test_timestamp_boundaries.cpp` constructs the corpus deterministically;
there is no random seed, external input, or downloaded dataset. Each line uses
this synthetic template, with a substituted month/day:

```text
Mar 257 08:30:00 example-host sshd[4200]: Failed password for user-a from 203.0.113.10 port 50101 ssh2
```

The explicit 257 witness runs first. The full corpus contains:

| Cases | Inputs / purpose |
| ---: | --- |
| 1 | Minimal positive wrap witness: day 257 |
| 2,049 | March day integers -1024..1024 inclusive |
| 124 | Valid days 1..31 shifted by -65536, -256, 256, 65536; none may alias |
| 8 | INT_MAX, INT_MIN, both adjacent overflow strings, `1x`, bytes `31 00`, bytes `31 ff`, and 4,096 ASCII nines |
| 1 | `01` remains accepted as day 1 |
| 744 | All months, days 1..31, in leap year 2024 and common year 2026 |
| **2,927** | **Total parse_line cases, including intentional overlap** |

An additional three-line stream contains valid day 1, invalid day 257, valid day 2.
It must emit two events and one timestamp warning, preserve line numbers 1/3/2,
and account for all three lines. The oracle uses explicit integer domain and
month lengths; it never constructs a `chrono::day` from an adversarial value.
For accepted values it also checks exact timestamp, line number, and cleared
error text. Rejected values check category and reason. INT overflow/invalid
bytes remain `invalid day token`; representable out-of-domain integers become
`invalid calendar date`.

## Commands and observed baseline

Commands below run from the repository root in a Linux shell. Build directories
are local only. The non-PIE flags select a fixed executable layout for this
local GCC sanitizer build; they are not project defaults or a product change.

At baseline `e2937e8`, before adding tests or changing production code:

```sh
cmake -S . -B build-reliability -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DLOGLENS_WARNINGS_AS_ERRORS=ON \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -fno-pie' \
  -DCMAKE_EXE_LINKER_FLAGS=-no-pie
cmake --build build-reliability -j 4
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-reliability --output-on-failure
```

Baseline: build succeeded; **7/7 CTest entries passed in 3.39 seconds**, no
ASan/UBSan findings. After adding only the new test and CMake registration:

```sh
cmake --build build-reliability --target test_timestamp_boundaries -j 4
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-reliability -R timestamp_boundaries --output-on-failure
```

Result: **0/1 passed**, CTest failure, `invalid day accepted at case 1`.
The test failed in 0.03 seconds (CTest total 0.05 seconds). This demonstrates
that the existing green suite did not detect invalid-day acceptance.

## Fixed implementation validation

After adding the pre-conversion 1..31 guard:

```sh
cmake --build build-reliability -j 4
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-reliability -R timestamp_boundaries -V
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-reliability --output-on-failure
```

Focused result: **2,927 cases and one three-line stream passed**, 0.07 seconds
(CTest total 0.10 seconds). Full result: **8/8 passed, 3.81 seconds**. No
ASan, leak, or UBSan findings were observed. All C++ targets in this build,
including the library and CLI, receive the sanitizer compile flags; Python
research tests run normally and are not C++ sanitizer coverage.

An additional non-sanitized optimized build uses:

```sh
cmake -S . -B build/reliability-release -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DLOGLENS_WARNINGS_AS_ERRORS=ON
cmake --build build/reliability-release -j 4
ctest --test-dir build/reliability-release --output-on-failure
git diff --check
```

Release build succeeded: **8/8 passed in 2.06 seconds**. Warnings-as-errors applies
to both builds. No dedicated formatter/type-check target is configured; the
compiler and test suite provide the applicable checks here.

## Focused libFuzzer execution

The new optional `fuzz_timestamp_day` target uses the existing instrumented
`loglens_fuzz_lib`. It substitutes arbitrary bytes into the day token of one
fixed March 2026 SSH failure line. Empty inputs and tokens containing ASCII
whitespace return early to keep envelope injection outside this target.
An independent integer-domain check requires acceptance exactly when the
complete token parses as an integer in 1..31, then checks the timestamp.
It shares `from_chars` with production, so it is not an independent lexical
oracle; its independent property is validation before narrowing. Rejections
must retain timestamp telemetry. The existing general parser fuzzer alone
would not detect this bug because an incorrectly accepted event still meets
its type/program invariants.

Three committed seeds contain exact ASCII bytes without newlines: `257`,
`-255`, `31`. Mutated corpus entries stay in an ignored build directory.
Installation (as root), followed by the build/run from the repository root:

```sh
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clang libclang-rt-dev
clang++ --version
cmake -S . -B build/reliability-fuzz -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF -DLOGLENS_BUILD_FUZZERS=ON \
  -DLOGLENS_WARNINGS_AS_ERRORS=ON -DCMAKE_CXX_FLAGS=-fno-sanitize-recover=all
cmake --build build/reliability-fuzz --target fuzz_timestamp_day -j 4
mkdir -p build/reliability-fuzz/day-corpus
cp tests/fuzz/corpus/timestamp_day/* build/reliability-fuzz/day-corpus/
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ./build/reliability-fuzz/fuzz_timestamp_day -runs=10000 -seed=20261015 \
  -max_len=4096 -timeout=2 -print_final_stats=1 build/reliability-fuzz/day-corpus
```

For a fresh replay, use a fresh build/corpus directory containing only those
three seeds. Mutation sequences and coverage counts can vary with toolchain.
The run count includes harness calls that skip empty/whitespace tokens; it is
not the number of distinct inputs or accepted parser calls. The maximum length
is a cap, not a claim that fuzzing exercised all sizes up to that length; the
deterministic test separately covers the 4,096-digit token.

Observed result: exit 0, **10,000 executed units**, no oracle failure, crash,
timeout, ASan, leak, or UBSan diagnostic. libFuzzer reported `cov: 227`,
`ft: 288`, final corpus 25 entries / 268 bytes, peak RSS 40 MB, and elapsed
`0 second(s)` at its whole-second resolution (not zero execution cost).
Its final growth limit was 80 bytes; this run did not reach the 4,096-byte cap.
These coverage counters are build-specific feedback, not source-line coverage
percentages or evidence of all paths being covered.

Final integration check also built both optional fuzz executables and reran the
Release suite after the CMake addition:

```sh
cmake --build build/reliability-fuzz --target fuzz_parser fuzz_timestamp_day -j 4
cmake --build build/reliability-release -j 4
ctest --test-dir build/reliability-release --output-on-failure
git diff --cached --check
```

Both fuzz targets built successfully; Release CTest passed **8/8 in 1.97 seconds**.
Diff whitespace checks passed. Final source/doc review and a scoped scan found
no private machine paths, personal identifiers, or credential patterns in the
new artifacts; only synthetic fixture identities are included.

## Interpretation

The production diff is a five-line guard/comment, with CTest registration,
deterministic tests, a focused fuzz oracle/corpus, and contract/evidence documentation. The new test is part
of ordinary CTest, so existing Linux/Windows CI definitions will discover it
when a future authorized push occurs; remote CI was not run here.

This is semantic regression evidence and bounded dynamic sanitizer/fuzz evidence,
not exhaustive memory safety, exhaustive fuzz coverage, or a performance benchmark.
No default detection algorithm, frozen experiment, source dataset, or existing
golden was changed. Fixtures use reserved documentation addresses and synthetic
identities. No push, PR, merge, tag, or release was performed.
