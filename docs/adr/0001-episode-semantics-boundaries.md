# ADR 0001: Episode Semantics Boundaries for v0.7 Research

- Status: Proposed
- Date: 2026-08-08
- Owner: stacknil

## Context

LogLens v0.6 reports repeated findings as detector episodes. The public v0.6
contract names four policy points: threshold crossing, maximal window,
non-overlapping windows, and cooldown merge. An episode is a reporting unit,
not an incident boundary.

The current implementation groups each rule subject by source IP or username,
sorts its signals by time, cuts an activity segment when an adjacent event gap
is greater than the rule window, and selects one best sliding window inside
each segment. The selected window must meet the rule threshold before a finding
is emitted. See [`src/detector.cpp`](../../src/detector.cpp) and the v0.6
[`Episode Policy`](../release-v0.6.0.md#episode-policy).

This baseline is deterministic and works for clearly separated bursts. It has
an important research boundary: a continuous low-density background stream can
keep two dense peaks in the same activity segment. The best-window selection
then emits one peak and can hide the fact that a second dense peak exists.

For example, with a ten-minute rule window and five-event threshold, sparse
background events every nine minutes can connect two five-event bursts. There
is no adjacent gap large enough to cut the segment, even if the two bursts are
far apart in aggregate time. Under the current algorithm, the segment is
eligible for one best-window selection; it is not eligible for two peak-based
episodes merely because its internal density is bimodal.

This is a v0.7 research boundary, not a v0.6 release blocker. The v0.6
algorithm and report contract remain unchanged by this ADR.

## Decision

Keep the v0.6 episode algorithm unchanged and make the following semantics
explicit for v0.7 research:

1. **Threshold crossing** is an eligibility event. The first window that meets
   the threshold proves that a candidate can emit a finding; it does not by
   itself define the episode start or the final reported window.
2. **Maximal window** means the selected highest-signal window under the rule's
   objective. In v0.6 this is a best-count sliding window (or the
   distinct-username objective for multi-user probing), not the longest possible
   time span. Tie-breaking and whether a candidate may be extended without
   increasing its score are v0.7 research questions.
3. **Non-overlapping episode** has two candidate-v1 boundaries. Search windows
   may share event IDs and time intervals. Selection compatibility separately
   requires a later window to start more than one rule window after the prior
   window ends. At publication, selected episodes inside a segment must have
   disjoint event-ID sets; the oracle validator fails closed on reuse. This does
   not define cross-rule evidence reuse or a future production signal budget.
4. **Cooldown merge** currently means that adjacent signals with a gap less
   than or equal to the rule window remain in one candidate segment. A gap
   larger than the rule window starts another segment. This is an adjacency
   rule, not a density-aware model of background activity.
5. **Continuous background with two dense peaks** is a required research fixture
   category. The fixture must preserve the sparse bridge events, show both
   dense peaks, and record that the v0.6 baseline may return one finding. A
   candidate v0.7 algorithm may split the peaks only with an explicit, tested
   separation policy.

No detector implementation change is part of this ADR. The first v0.7 change
should be a fixture and oracle that makes the baseline behavior measurable
before a new segmentation algorithm is selected.

## Research fixture contract

The fixture should use sanitized synthetic events and a fixed rule configuration
that makes each boundary observable. At minimum it should cover:

| Case | Required observation |
| --- | --- |
| Isolated dense bursts | Two bursts separated by a gap greater than the rule window produce two baseline episodes. |
| Continuous bridge | Two dense bursts connected by background gaps at or below the rule window remain one baseline segment. |
| Threshold edge | A candidate exactly at threshold is eligible; one event below threshold is not. |
| Maximal-window tie | Equal-score windows have a documented deterministic tie-break. |
| Shared evidence | Overlapping search candidates expose shared event IDs; selected episodes materialize each event ID at most once, and reuse fails closed. |
| Cooldown boundary | A gap exactly at the rule window and one second beyond it test the inclusive boundary. |
| Bimodal background | Two dense peaks are surrounded by lower-rate background, with expected baseline output recorded separately from the research candidate output. |

Each case should record raw event IDs, timestamps, rule window, threshold,
candidate windows, selected windows, episode indexes, and the reason an event
was included or excluded. The fixture must not claim compromise, intent,
attribution, or an incident boundary.

## Candidate experiment: window-separated weighted intervals

The 2026-08-25 experiment tests one narrow hypothesis: after v0.6 activity
segmentation, a deterministic global selection over dense windows can recover
both peaks in the continuous-background fixture without reusing event evidence.
It does not select the v0.7 production algorithm.

The research evaluator enumerates every contiguous window that meets the
threshold inside the inclusive rule window. It then selects a compatible set
with these ordered objectives:

1. A later selected window must start strictly more than one rule window after
   the previous selected window ends. An exact-boundary gap remains one cooldown
   episode.
2. Maximize the total number of covered events.
3. Minimize total selected-window span, then episode count.
4. Resolve a remaining tie by the chronological window key.

This first slice adds only the bounded selection core and boundary tests.
Exhaustive window materialization copies many event-ID sequences, and selection
scans candidate predecessors. Worst-case cost is super-quadratic, so the core
rejects more than 200 fixture events or 1,000 candidates per segment. These
limits make research execution bounded; they do not make the algorithm suitable
for `Detector::analyze()`.

A fail-closed baseline contract is a separate prerequisite for oracle
materialization. Candidate v1 accepts only the `brute_force` / `source_ip` /
inclusive-window fixture contract, replays the v0.6 best-count selection, and
requires the declared segments, selected window, finding identity, and excluded
event partition to match that replay. Timestamp comparison uses instants and
finding identity uses canonical UTC, so equivalent offsets cannot create a new
episode identity. Rule scalars are type-strict: the subject is a string, threshold
and window_seconds are integers, and the terminal-failure flag is a Boolean.
Coercible strings and numeric Boolean equivalents fail closed. Unsupported rules
or semantically stale baselines are rejected before candidate selection.

The oracle slice consumes that baseline contract and requires candidate,
episode, and event-decision references to agree before materializing output.

On `continuous_background_two_peaks`, the v0.6 baseline emits one episode. The
candidate emits two: `line:1` through `line:5` and `line:11` through `line:15`.
It covers ten dense-peak events exactly once, excludes the five bridge events,
and materializes these deterministic IDs:

- `finding:brute_force:584fd14b544a7959`
- `finding:brute_force:a885dcb623777120`

Reversing the fixture input produces the same ordered oracle. Boundary tests
also retain one episode at an exact 600-second cooldown gap and permit two at
601 seconds.

The `isolated_dense_bursts` null control uses the same threshold of five and
inclusive 600-second rule window. Its two five-event bursts have a 1,080-second
inter-segment gap. Both the replayed v0.6 baseline and the candidate emit two
episodes, preserve all ten events exactly once, report no exclusions, and keep
`continuous_segment_split` false. The candidate preserves these deterministic
finding IDs:

- `finding:brute_force:883357c5e7697574`
- `finding:brute_force:ba242483f59f6f4e`

Reversing the input or replacing timestamps with equivalent timezone offsets
does not change the ordered oracle. This accepts the candidate as compatible
with already-correct isolated segmentation for this bounded null control; it
does not expand the candidate's production scope.

A focused maximal-window tie control uses six events at offsets 0, 1, 2, 3,
600, and 601 seconds. With threshold five and the inclusive 600-second window,
the only candidates are `line:1` through `line:5` and `line:2` through
`line:6`. Both cover five events, span 600 seconds, and require one episode, so
the chronological window key is the first objective that can distinguish them.
The earlier candidate wins for both forward and reversed candidate input. This
accepts the final tie-break and candidate-order invariance for that bounded
control; it does not settle the separate shared-evidence policy.

A focused shared-evidence control uses six events at offsets 0 through 5
seconds. With threshold five, enumeration produces `line:1` through `line:5`,
`line:1` through `line:6`, and `line:2` through `line:6`; `line:2` through
`line:5` belong to all three search candidates. Candidate v1 selects the
six-event maximal window and materializes each event ID once. A separate
negative control gives two distinct selected candidates the same event-ID set;
oracle validation rejects it as `selected episodes reuse event evidence`.
Mutation testing confirms that disabling this guard makes the focused test
fail. This accepts event IDs as the candidate-v1 publication non-overlap unit,
not as a cross-rule or production policy.

A focused uniform-background alert-volume control uses events exactly 150
seconds apart with threshold five and the inclusive 600-second window. Thirteen
events remain one activity segment and produce one selected candidate. Adding a
fourteenth equally spaced event still leaves one baseline segment but makes
candidate v1 select `line:1` through `line:5` and `line:10` through `line:14`.
There is no density contrast or peak prominence separating these windows. This
falsifies the hypothesis that candidate episode multiplication by itself proves
multiple dense peaks. It blocks production adoption without a calibrated
density-contrast rule or an explicit alert-volume budget; it does not estimate
a real-world false-positive rate.

Together, the two fixtures and focused tie/shared-evidence/background controls
accept the recovery, null-control, deterministic tie-break, and publication
single-consumption hypotheses for their bounded cases. The background control
also resolves one qualitative safety decision: candidate v1 must not move into
production unchanged. Quantitative alert-volume calibration and a production
complexity design still require independent evidence. `Detector::analyze()` and
`loglens.report.v3` remain unchanged.

## Alternatives considered

- **Keep adjacent-gap segmentation as the final model** - simple and
  deterministic, but it cannot distinguish a continuous background bridge from
  a single coherent burst.
- **Split every local density peak** - can expose bimodal activity, but needs
  explicit peak prominence, minimum separation, and noise-handling parameters;
  it may over-split one operational burst.
- **Use a density-aware cooldown or bridge budget** - directly targets the
  continuous-background case, but introduces additional policy knobs and needs
  fixture-backed calibration before it can become a stable contract.
- **Emit all threshold-crossing windows** - preserves more evidence, but creates
  overlapping findings and makes `finding_id`, episode identity, and downstream
  deduplication ambiguous.

## Consequences

- v0.6 remains stable and does not acquire an untested density model.
- v0.7 gets a concrete research target instead of an ambiguous request to
  "improve episodes."
- A future algorithm must be compared with the current baseline on the same
  fixture, including cases where the baseline behavior is intentionally
  preserved.
- The report contract may need an explicit candidate/selection distinction if
  v0.7 emits multiple peak candidates from one continuous segment.

## References

- [`v0.6 Episode Policy`](../release-v0.6.0.md#episode-policy)
- [`Detector implementation`](../../src/detector.cpp)
- [`Detector tests`](../../tests/test_detector.cpp)
- [`Candidate selection core`](../../scripts/episode_candidate_core.py)
- [`Candidate core tests`](../../tests/test_episode_candidate_core.py)
- [`Baseline contract`](../../scripts/episode_baseline_contract.py)
- [`Baseline contract tests`](../../tests/test_episode_candidate_baseline_contract.py)
- [`Candidate evaluator`](../../scripts/evaluate_episode_candidate.py)
- [`Candidate regression tests`](../../tests/test_episode_candidate.py)
- [`Continuous-background candidate oracle`](../../tests/fixtures/episode_semantics_v0.7/continuous_background_two_peaks/candidate.window-separated-v1.expected.json)
- [`Isolated-burst candidate oracle`](../../tests/fixtures/episode_semantics_v0.7/isolated_dense_bursts/candidate.window-separated-v1.expected.json)
