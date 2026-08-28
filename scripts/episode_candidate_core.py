"""Bounded research core for deterministic episode candidate selection."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
from typing import Any, Sequence


MAX_FIXTURE_EVENTS = 200
MAX_CANDIDATES_PER_SEGMENT = 1_000


@dataclass(frozen=True)
class CandidateWindow:
    event_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    threshold_crossing_event_id: str

    @property
    def candidate_id(self) -> str:
        return f"candidate:{self.event_ids[0]}..{self.event_ids[-1]}"

    @property
    def event_count(self) -> int:
        return len(self.event_ids)

    @property
    def span_seconds(self) -> int:
        return int((self.last_seen - self.first_seen).total_seconds())


def parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("timestamp must use ISO 8601 syntax") from error
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed


def ordered_events(events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(events) > MAX_FIXTURE_EVENTS:
        raise ValueError(
            f"research evaluator accepts at most {MAX_FIXTURE_EVENTS} events"
        )
    event_ids = [str(event["event_id"]) for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("event IDs must be unique")
    return sorted(
        events,
        key=lambda event: (
            parse_timestamp(str(event["timestamp"])),
            int(event["line_number"]),
            str(event["event_id"]),
        ),
    )


def enumerate_candidate_windows(
    events: Sequence[dict[str, Any]], threshold: int, window_seconds: int
) -> list[CandidateWindow]:
    """Enumerate every contiguous threshold window inside the inclusive rule window."""
    if threshold < 1 or window_seconds < 1:
        raise ValueError("threshold and window_seconds must be positive")
    ordered = ordered_events(events)
    candidates: list[CandidateWindow] = []
    for start in range(len(ordered)):
        first_seen = parse_timestamp(str(ordered[start]["timestamp"]))
        for end in range(start, len(ordered)):
            last_seen = parse_timestamp(str(ordered[end]["timestamp"]))
            if (last_seen - first_seen).total_seconds() > window_seconds:
                break
            if end - start + 1 < threshold:
                continue
            candidates.append(
                CandidateWindow(
                    event_ids=tuple(
                        str(event["event_id"]) for event in ordered[start : end + 1]
                    ),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    threshold_crossing_event_id=str(
                        ordered[start + threshold - 1]["event_id"]
                    ),
                )
            )
            if len(candidates) > MAX_CANDIDATES_PER_SEGMENT:
                raise ValueError(
                    "research evaluator candidate limit exceeded "
                    f"({MAX_CANDIDATES_PER_SEGMENT} per segment)"
                )
    return candidates


def _selection_score(selection: Sequence[CandidateWindow]) -> tuple[int, int, int]:
    return (
        sum(candidate.event_count for candidate in selection),
        -sum(candidate.span_seconds for candidate in selection),
        -len(selection),
    )


def _selection_key(selection: Sequence[CandidateWindow]) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        (candidate.first_seen, candidate.last_seen, candidate.event_ids)
        for candidate in selection
    )


def _prefer(
    left: list[CandidateWindow], right: list[CandidateWindow]
) -> list[CandidateWindow]:
    left_score = _selection_score(left)
    right_score = _selection_score(right)
    if left_score != right_score:
        return left if left_score > right_score else right
    return left if _selection_key(left) <= _selection_key(right) else right


def select_window_separated_candidates(
    candidates: Sequence[CandidateWindow], window_seconds: int
) -> list[CandidateWindow]:
    """Select an optimal set whose adjacent windows are more than one rule window apart."""
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            candidate.last_seen,
            candidate.first_seen,
            candidate.event_ids,
        ),
    )
    best: list[list[CandidateWindow]] = [[]]
    for index, candidate in enumerate(ordered):
        predecessor = -1
        for prior in range(index - 1, -1, -1):
            gap = (candidate.first_seen - ordered[prior].last_seen).total_seconds()
            if gap > window_seconds:
                predecessor = prior
                break
        take = best[predecessor + 1] + [candidate]
        best.append(_prefer(take, best[index]))
    return sorted(
        best[-1],
        key=lambda candidate: (
            candidate.first_seen,
            candidate.last_seen,
            candidate.event_ids,
        ),
    )


def _duration_microseconds(start: datetime, end: datetime) -> int:
    delta = end - start
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000
        + delta.microseconds
    )


def selection_has_minimum_gap_contrast(
    events: Sequence[dict[str, Any]],
    selected: Sequence[CandidateWindow],
    minimum_ratio: int | Fraction = 2,
) -> bool:
    """Return whether every selected-window gap meets an exact mean-gap ratio."""
    if (
        isinstance(minimum_ratio, bool)
        or not isinstance(minimum_ratio, (int, Fraction))
        or minimum_ratio <= 0
    ):
        raise ValueError("minimum_ratio must be a positive integer or Fraction")

    ordered = ordered_events(events)
    timestamps = [parse_timestamp(str(event["timestamp"])) for event in ordered]
    event_positions = {
        str(event["event_id"]): index for index, event in enumerate(ordered)
    }
    chronological = sorted(
        selected,
        key=lambda candidate: (
            candidate.first_seen,
            candidate.last_seen,
            candidate.event_ids,
        ),
    )

    consumed: set[str] = set()
    for candidate in chronological:
        if candidate.event_count < 2:
            raise ValueError("selected candidates must contain at least two events")
        if len(candidate.event_ids) != len(set(candidate.event_ids)):
            raise ValueError("selected candidate event IDs must be unique")
        if any(event_id not in event_positions for event_id in candidate.event_ids):
            raise ValueError("selected candidate references an unknown event")
        positions = [event_positions[event_id] for event_id in candidate.event_ids]
        if positions != list(range(positions[0], positions[-1] + 1)):
            raise ValueError("selected candidate events must be contiguous and ordered")
        if (
            candidate.first_seen != timestamps[positions[0]]
            or candidate.last_seen != timestamps[positions[-1]]
        ):
            raise ValueError("selected candidate boundaries must match its events")
        if candidate.threshold_crossing_event_id not in candidate.event_ids:
            raise ValueError("threshold crossing must belong to its candidate")
        if consumed.intersection(candidate.event_ids):
            raise ValueError("selected candidates reuse event evidence")
        consumed.update(candidate.event_ids)

    for left, right in zip(chronological, chronological[1:]):
        if right.first_seen <= left.last_seen:
            raise ValueError("selected candidate windows must not overlap")

        left_mean_gap = Fraction(
            _duration_microseconds(left.first_seen, left.last_seen),
            left.event_count - 1,
        )
        right_mean_gap = Fraction(
            _duration_microseconds(right.first_seen, right.last_seen),
            right.event_count - 1,
        )
        bridge_event_count = bisect_left(timestamps, right.first_seen) - bisect_right(
            timestamps, left.last_seen
        )
        bridge_mean_gap = Fraction(
            _duration_microseconds(left.last_seen, right.first_seen),
            bridge_event_count + 1,
        )
        if bridge_mean_gap < minimum_ratio * max(left_mean_gap, right_mean_gap):
            return False

    return True


def activity_segments(
    events: Sequence[dict[str, Any]], window_seconds: int
) -> list[list[dict[str, Any]]]:
    ordered = ordered_events(events)
    if not ordered:
        return []
    segments: list[list[dict[str, Any]]] = [[ordered[0]]]
    for event in ordered[1:]:
        previous = segments[-1][-1]
        gap = (
            parse_timestamp(str(event["timestamp"]))
            - parse_timestamp(str(previous["timestamp"]))
        ).total_seconds()
        if gap > window_seconds:
            segments.append([])
        segments[-1].append(event)
    return segments
