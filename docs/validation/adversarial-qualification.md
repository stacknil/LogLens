# Adversarial qualification design and progress

Status: QUALIFICATION_READY for the bounded local campaign; SDK blocker resolved.
GCC, Clang ASan/UBSan and MSVC CTest each passed 11/11. This is
local qualification evidence, not a claim of complete memory safety.

## Baseline and isolation

The local qualification baseline is `6aef72ea5c6eb2657e6e01fe558d257e04997ca8`,
including the existing stream-completion correction. It descends from the local
main reference `2ab31a057206822fe0a526b849f0f836bd131a37`. The remote repository
was not queried: this campaign is offline. This choice exercises the existing
stream tests instead of rediscovering an already implemented transport fix.
No pre-existing checkout, research experiment, corpus or golden is changed.
All work remains local and uncommitted.

## Failure model and oracle independence

| Boundary | Failure / expected behavior | Observable oracle |
|---|---|---|
| Bytes to envelope | Truncation, NUL, control and non-UTF-8 bytes; malformed input must not crash | Bounded byte corpus, ASan/UBSan; explicit supported fixtures |
| Envelope to timestamp | Invalid calendar/clock/offset must reject; equivalent supported offsets denote one instant | Fixed epoch anchors and integer arithmetic, independent of production parsing |
| Envelope to dispatch | Program/PID variations must preserve supported auth semantics | Authored program/message/type/field table |
| Auth classification | Command payload must not become log metadata; unsupported evidence remains warning telemetry | Explicit expected classification and deliberate event/warning substitution controls |
| Event normalization | Malformed source tokens must not enter source-IP detector groups | Authored valid/invalid address cases; independently inspect emitted source fields |
| Event to signal | Audit-only events and successes do not become terminal failures; PAM remains lower-confidence | Explicit default eligibility table, not production mapping output |
| Signal to episodes | Inclusive time windows, threshold, grouping, highest-signal selection, unique line references | Small exhaustive window model and fixed separated-episode witnesses |
| Events to reports | Deterministic valid artifacts, complete counts, escaped fields and formula neutralization | Standard-library JSON/CSV consumers, decoded field expectations, repeated rendering |
| Stream completion | Transport error cannot return a successful partial parse | Existing injected streambuf faults and independent negative control |
| Resource use | Small adversarial records must not cause unbounded work | Fixed byte/line caps, process timeout/RSS observations, matched Release workloads |

Crash freedom, parser classification, detector semantics, report validity and
resource behavior are separate claims. Sanitizer success does not establish
semantic correctness. Reporting determinism requires fixed explicit metadata
and fixed input-file contents, since host warning summaries reread the source.
Fuzz-generated paths must never select files on the host.

## Executable invariant catalog

1. Authored supported message families retain expected type, username and source.
2. Equivalent supported syslog/journalctl envelopes retain auth fields and instant.
3. Individual-line and complete-stream parsing agree, with explicit line identities.
4. Unsupported insertion cannot increase eligible signals or findings.
5. Unsupported evidence remains represented in warnings and category/bucket counts.
6. Blank insertion preserves auth semantics while adjusting source references/accounting.
7. Equivalent UTC and numeric offsets retain a fixed instant, including date rollover.
8. Invalid calendar/clock/offset tokens reject with timestamp taxonomy.
9. Malformed source tokens never become normalized trusted IP evidence.
10. Default signal eligibility matches the authored event-type table.
11. Threshold and inclusive time-window boundaries match an exhaustive small model.
12. Separated episodes retain distinct identities and exact evidence references.
13. Repeated rendering with fixed inputs produces identical artifacts.
14. JSON and CSV consumers recover the expected synthetic string values and structure.
15. CSV formula-leading fields remain neutralized after CSV decoding.
16. Global and host event counts conserve normalized input events.
17. Stream read failures remain failures, distinct from content warnings and EOF.
18. Sudo command payload text cannot reclassify an otherwise supported command record.

Negative controls must corrupt observations at the boundary consumed by each
oracle. A wrapper passes only if its targeted checker rejects the corruption;
merely throwing an unrelated error is insufficient. Retain positive witnesses
and each deliberate RED result alongside the enclosing GREEN self-test.

## Existing coverage and gaps

The existing parser fuzzer checks event type/program presence and failure-reason
presence, not normalized field correctness or detector consequences. The day
fuzzer checks one March day token. Parser properties cover handler permutation,
selected malformed addresses and arbitrary-byte result shape. Stream tests
already cover injected transport faults and EOF exception masks. Detector tests
and report goldens cover selected episodes and output examples. New work must
measure added reachable semantics rather than claim novelty from more runs.

## Progress journal

- Baseline GCC 13.3 Release with warnings-as-errors: CTest 9/9.
- Baseline Clang 18.1.3 ASan/UBSan: CTest 9/9.
- Existing parser and day targets: 2,000 executions each, seed 129130; no
  sanitizer finding in those bounded runs. Raw logs retained outside the source tree.
- Baseline CLI probes confirmed malformed IPv4/IPv6 admission, source-validation
  versus extraction disagreement, marker-word username loss, and sudo command/PWD
  text affecting classification. Retained original inputs and baseline outputs
  precede corrections; focused regressions demonstrate RED then GREEN.
- An independent strict UTF-8 JSON consumer rejected six baseline report cases.
  The correction passes all 17 authored cases with 51 artifact corruption controls.
- GCC warnings-as-errors and Clang ASan/UBSan CTest increased from 9 to 11 tests;
  both passed. Existing report goldens and CLI contracts passed unchanged.
- Three serial 60-second fuzz budgets completed successfully; table below records
  actual counts. A later strengthened sequence oracle replayed the retained corpus
  without mutation and passed a 2,000-run smoke.
- A separate deterministic report byte-mutation campaign passed 273 cases under
  ASan/UBSan, with 819 JSON/CSV corruption controls detected. This is boundary
  testing through independent consumers, not coverage-guided report fuzzing.
- Six paired performance workloads completed with three trials per build.
- Initial MSVC 19.51.36256.0 configuration failed before project compilation:
  Windows SDK `rc` and `mt` were unavailable. After explicit installation
  authorization, SDK 10.0.26100.7705 and isolated Python test dependencies were
  installed. The first Windows build succeeded but CTest exposed a CSV newline
  preservation defect (10/11); the failure and original artifacts are retained.
- Only CSV output streams now use binary mode. Rebuilt MSVC Release with `/W4
  /WX` passed CTest 11/11, including the unchanged failing CRLF fixture. The
  independent reviewer reproduced the 17-case/51-control GREEN consumer result
  and found no conflict with the documented CSV contract.
- After the CSV correction, GCC and Clang sanitizer builds and full CTest passed
  again. Both Windows and Linux ASan extended report runs passed all 273 cases
  and detected 819 corruption controls each. Existing goldens remain unchanged.
- Final source validation rebuilt both Linux configurations and passed CTest
  11/11 in each; all three retained fuzz corpora replayed successfully without
  mutation, followed by 2,000 executions per target. The final report boundary
  campaign again passed 273 cases and 819 controls. Host/PID variation adds 18
  explicit envelope checks. No goldens or detector implementations changed.
- An independent read-only reviewer approved with limitations, reran the final
  semantic executable successfully, and separately executed the earlier
  17-case/51-control report consumer. Their inspection of full-suite and extended
  campaign logs is not claimed as independent execution of those campaigns.
- Performance artifact inspection confirmed equal parsed/warning/finding counts
  across all baseline/candidate pairs; artifact byte sizes are recorded privately.
- Final pre-commit audit reproduced `PWD=/tmp/COMMAND=marker` without an actual
  command field as a false sudo command; three copies produced a sudo burst.
  Recognition now requires a field start (start of details or after the sudo
  ` ; ` audit separator), never a substring inside a value. The permanent
  negative regression was RED before the correction and GREEN afterward in both
  input formats, alongside supported command and existing denial/failure cases.
  GCC, Clang ASan/UBSan and MSVC CTest each passed 11/11 again; the pipeline
  sanitizer smoke completed 2,000 runs. The exact three-line CLI reproduction
  now yields zero events, three `sudo_other` warnings and zero findings.

## Final audit boundary

The original timed campaigns belong to checkpoint tree
`2cd0b9f551e3eaba5e5276d9b2c71f648f847bf6`. Subsequent changes strengthened
field/one-to-one finding checks, preserved bare-`::` rejection, added envelope
regressions, and extended report byte mutation. A subsequent Windows-only CSV
translation defect required a narrow file-output correction. Final rebuild, CTest, corpus
replay and bounded smoke evidence validate those later changes; the original
timed coverage counters must not be attributed to the final binary. The final
staged tree identity and exact local commands are in the private evidence manifest.

Remaining limitations: no remote CI, no exhaustive IPv6
language proof, no arbitrary detector configuration model, no native-filesystem
performance conclusion, and no coverage-guided report fuzzer. Report byte
mutation instead exercises actual serialization under sanitizers and independent
standard-library consumers. Existing injected stream faults cover transport
integrity; no new transport implementation was introduced. The independent
review found no unresolved material source defect. Windows tests use MSVC Release;
sanitizer evidence is Linux Clang only. Qualification is bounded to the recorded
inputs and configurations; it is neither complete memory-safety proof nor
publication authorization. All changes remain local and uncommitted.

## Confirmed repairs and compatibility

| Failure | Minimal correction | Regression boundary |
|---|---|---|
| Trailing-dot IPv4, incomplete/triple-colon IPv6 admitted | Decimal octets and IPv6 group/compression accounting | Explicit malformed rejection and valid token preservation |
| Source classifier validated a different token than handler emitted | Validate normalized source after successful dispatch | Adversarial username/source markers, exact emitted fields |
| Username `from` mistaken for delimiter | Extract source from the remainder after consuming username | Six SSH families, both envelopes |
| Sudo command/PWD value treated as authentication metadata | Match leading auth/denial metadata before command payload | Exact classification, no extra detector evidence |
| PWD value containing `COMMAND=` admitted as a command audit | Recognize `COMMAND=` only at audit-field starts | Missing-field negative and supported command positive witnesses through detector |
| Invalid UTF-8 emitted directly into JSON | Preserve valid Unicode and escape each malformed byte as `\u00XX` | Independent Python UTF-8/JSON decoder, byte mutation controls |
| Windows text output changes CSV field CRLF into CRCRLF | Open only CSV output files in binary mode | Existing CRLF field fixture fails before fix, passes after fix |

No rule, threshold, signal eligibility, schema version, CSV serializer, golden,
or timestamp implementation changes are made. Parser corrections can change
counts for affected malformed/opaque inputs; that is the intended repair.
The existing rejection of bare `::` remains: this campaign does not broaden that
accepted-source policy. Textual IPv6 spellings are not canonicalized or regrouped.
JSON's malformed-byte representation is explicit and deterministic, but not an
injective encoding of arbitrary original bytes: an invalid byte and valid Unicode
can represent the same decoded character. Raw evidence remains the provenance
source; this correction does not promise byte recovery from JSON. CSV columns,
quoting and formula neutralization remain unchanged. Windows CSV record
separators change from CRLF to LF, and embedded field CR/LF bytes are preserved
exactly as rendered. The documented contract does not prescribe record terminator
bytes. JSON and Markdown retain their existing file modes. Reports never use fuzz
input as a filesystem path.

Rejected alternatives: scan all message text for source/denial markers (opaque
payload confusion); use production detector output as expected values (tautology);
rewrite detector grouping (outside confirmed defects); replace report goldens
(would conceal compatibility failures). Rollback is reverting the local candidate
diff; no remote state or stored research data has been migrated.

## Measured sanitizer campaigns

Clang 18.1.3, ASan with leak detection, UBSan halt-on-error; seed 129130.
Serial workers, timeout 3 seconds/input, RSS limit 1,024 MiB; maximum inputs
4,096 / 32 / 97 bytes respectively. Counts include initial corpus processing.

| Target | Executions | Actual reported seconds | Initial to final cov / ft | Peak RSS MiB |
|---|---:|---:|---|---:|
| parser | 1,092,204 | 62 | 551/715 to 1002/1807 | 490 |
| timestamp day | 14,875,968 | 61 | 296/361 to 319/432 | 540 |
| structured pipeline | 131,105 | 62 | 1979/4380 to 2585/12279 | 491 |

These are libFuzzer instrumentation counters for each particular binary, not
source-line coverage percentages or comparable cross-binary coverage scores.
No sanitizer finding or crash occurred. Original logs include an ignored
`-max_number_of_features` warning: that unsupported flag has been removed from
the reproduction script. The other stated caps were active. Absence of failure
does not prove memory safety. Additional random duration was not used merely to
fill the suggested maximum budget; deterministic semantic gaps took priority.

## Performance observations

GCC 13.3 Release, same WSL instance and filesystem, 3,000 synthetic records per
workload, three trials each, alternating baseline/candidate order. CLI parsing,
detection and report writing are included; `/usr/bin/time` supplies peak RSS.
Median wall times rounded to hundredths of a second:

| Workload | Baseline seconds | Candidate seconds |
|---|---:|---:|
| Dense failures | 0.04 | 0.04 |
| Unsupported | 0.06 | 0.06 |
| 4 KiB command payload | 0.35 | 0.36 |
| Distinct subjects | 0.04 | 0.04 |
| Inclusive window boundary | 0.04 | 0.04 |
| Mixed evidence | 0.06 | 0.06 |

Observed peak RSS was below 31 MiB in both builds. All 36 invocations exited zero.
The original distinct-subject generator used addresses outside documentation
ranges; its measurements are retained privately as superseded evidence. Only
that workload was regenerated using `2001:db8::/32` and rerun after the final
sudo correction: 3,000 records and 3,000 distinct subjects, with the original
65,024-subject repetition period preserved. Three trials per build produced
median wall times 0.043066 seconds (baseline) and 0.041555 seconds (candidate),
rounded in the table above. All six runs parsed 3,000 events with no warnings or
findings. Changing the address family means these measurements must not be used
to claim a speedup against the superseded IPv4 workload. Other workload evidence
was not regenerated during the narrow final audit. Use `--workload distinct-subjects`
with the measurement script to reproduce only this corrected comparison.
These short DrvFS measurements show no obvious regression at this scale; they are
not a native Linux throughput benchmark, statistical equivalence result, or an
asymptotic resource guarantee. Raw individual timings and exact commands are
retained in the private manifest.

## Reproduction (Linux, from repository root)

```sh
python3 scripts/run-adversarial-qualification.py --evidence ../qualification-run --seconds 60
python3 tests/test_adversarial_reports.py ../qualification-run/build/report_adversarial_driver ../qualification-reports --extended
cmake -S . -B ../qualification-gcc -G Ninja -DCMAKE_BUILD_TYPE=Release -DLOGLENS_WARNINGS_AS_ERRORS=ON
cmake --build ../qualification-gcc -j2
ctest --test-dir ../qualification-gcc --output-on-failure
python3 scripts/measure-adversarial-performance.py --baseline ../baseline-build/loglens --candidate ../qualification-gcc/loglens --output ../qualification-performance
git diff --check
```

Use a separate archive of the pinned baseline for `baseline-build`, with identical
Release flags. Do not build over original checkouts. The campaign runner records
exact commands, exits, durations and sanitizer settings in `execution.json`;
the corpus generator emits provenance in `manifest.json`. Private baseline RED,
intermediate RED/GREEN and final validation records are kept separately, so a
successful retry cannot erase a failure. Extended campaigns remain local; CI adds
only deterministic corpus generation and a 2,000-run pipeline smoke. Remote CI
has NOT_RUN. No commit, push, publication or research modification is authorized.
