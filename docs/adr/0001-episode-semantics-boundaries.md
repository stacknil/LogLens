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
3. **Non-overlapping episode** is currently enforced by segment construction
   and one selection per segment. It does not yet describe a global candidate
   ranking problem where two windows compete for shared events. v0.7 must state
   whether exclusion is by event IDs, time intervals, or a rule-specific signal
   budget.
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
| Shared evidence | Overlapping candidate windows make the non-overlap unit explicit. |
| Cooldown boundary | A gap exactly at the rule window and one second beyond it test the inclusive boundary. |
| Bimodal background | Two dense peaks are surrounded by lower-rate background, with expected baseline output recorded separately from the research candidate output. |

Each case should record raw event IDs, timestamps, rule window, threshold,
candidate windows, selected windows, episode indexes, and the reason an event
was included or excluded. The fixture must not claim compromise, intent,
attribution, or an incident boundary.

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
