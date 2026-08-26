"""Fail-closed binding between a research fixture and its v0.6 baseline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

if __package__:
    from .episode_candidate_core import (
        CandidateWindow,
        activity_segments,
        ordered_events,
        parse_timestamp,
    )
else:
    from episode_candidate_core import (
        CandidateWindow,
        activity_segments,
        ordered_events,
        parse_timestamp,
    )


RULE_FIELDS = (
    "rule_id",
    "grouping_key",
    "subject",
    "threshold",
    "window_seconds",
    "window_boundary",
)
SUPPORTED_RULE = {
    "rule_id": "brute_force",
    "grouping_key": "source_ip",
    "window_boundary": "inclusive",
    "signal_kind": "ssh_failed_password",
    "counts_as_terminal_auth_failure": True,
}
BASELINE_ALGORITHM = {
    "id": "v0.6.activity_segments_best_count_window",
    "implementation": "src/detector.cpp",
    "segment_boundary": "split when an adjacent event gap is greater than the rule window",
    "selection_tie_break": "keep the first maximum encountered in chronological scan order",
}


@dataclass(frozen=True)
class BaselineContext:
    segments: list[list[dict[str, Any]]]
    selections: tuple[CandidateWindow, ...]
    episode_count: int


def rule_projection(rule: dict[str, Any]) -> dict[str, Any]:
    return {key: rule[key] for key in RULE_FIELDS}


def canonical_oracle_timestamp(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_finding_timestamp(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _hash_append(value: int, text: str) -> int:
    for byte in text.encode("utf-8"):
        value ^= byte
        value = (value * 1099511628211) & ((1 << 64) - 1)
    value ^= 0xFF
    return (value * 1099511628211) & ((1 << 64) - 1)


def finding_id(rule: dict[str, Any], candidate: CandidateWindow) -> str:
    value = 14695981039346656037
    fields = [
        str(rule["rule_id"]),
        str(rule["grouping_key"]),
        str(rule["subject"]),
        canonical_finding_timestamp(candidate.first_seen),
        canonical_finding_timestamp(candidate.last_seen),
        str(rule["threshold"]),
        str(candidate.event_count),
        str(candidate.event_count),
        *candidate.event_ids,
    ]
    for field in fields:
        value = _hash_append(value, field)
    return f"finding:{rule['rule_id']}:{value:016x}"


def _validate_fixture(fixture: dict[str, Any]) -> None:
    if fixture.get("format") != "loglens.episode_research_fixture.v1":
        raise ValueError("unsupported research fixture format")
    rule = fixture["rule"]
    if any(rule.get(field) != value for field, value in SUPPORTED_RULE.items()):
        raise ValueError(
            "candidate v1 supports only brute_force source_ip terminal-failure rules"
        )
    subject = str(rule.get("subject", ""))
    if not subject:
        raise ValueError("candidate v1 requires a non-empty source_ip subject")
    if int(rule.get("threshold", 0)) < 1 or int(rule.get("window_seconds", 0)) < 1:
        raise ValueError("candidate v1 threshold and window_seconds must be positive")
    if any(
        event.get("event_type") != SUPPORTED_RULE["signal_kind"]
        or str(event.get("source_ip", "")) != subject
        for event in fixture["events"]
    ):
        raise ValueError(
            "candidate v1 fixture events must match the brute_force rule subject"
        )


def _baseline_selections(
    segments: Sequence[Sequence[dict[str, Any]]],
    threshold: int,
    window_seconds: int,
) -> tuple[CandidateWindow, ...]:
    selections: list[CandidateWindow] = []
    for events in segments:
        start = 0
        best_start = 0
        best_end = 0
        best_count = 0
        for end, event in enumerate(events):
            end_timestamp = parse_timestamp(str(event["timestamp"]))
            while (
                start < end
                and (
                    end_timestamp
                    - parse_timestamp(str(events[start]["timestamp"]))
                ).total_seconds()
                > window_seconds
            ):
                start += 1
            count = end - start + 1
            if count > best_count:
                best_start, best_end, best_count = start, end, count
        if best_count < threshold:
            continue
        selected = events[best_start : best_end + 1]
        selections.append(
            CandidateWindow(
                event_ids=tuple(str(event["event_id"]) for event in selected),
                first_seen=parse_timestamp(str(selected[0]["timestamp"])),
                last_seen=parse_timestamp(str(selected[-1]["timestamp"])),
                threshold_crossing_event_id=str(
                    selected[threshold - 1]["event_id"]
                ),
            )
        )
    return tuple(selections)


def _expected_findings(
    rule: dict[str, Any], selections: Sequence[CandidateWindow]
) -> list[dict[str, Any]]:
    return [
        {
            "finding_id": finding_id(rule, candidate),
            "episode_index": index,
            "rule_id": "brute_force",
            "subject_kind": "source_ip",
            "subject": str(rule["subject"]),
            "grouping_key": "source_ip",
            "threshold": int(rule["threshold"]),
            "observed_count": candidate.event_count,
            "event_count": candidate.event_count,
            "window_start": canonical_finding_timestamp(candidate.first_seen),
            "window_end": canonical_finding_timestamp(candidate.last_seen),
            "evidence_event_ids": list(candidate.event_ids),
            "verdict_boundary": "triage_signal_not_compromise_or_attribution",
        }
        for index, candidate in enumerate(selections, start=1)
    ]


def _contiguous_events(
    event_ids: Sequence[str], segments: Sequence[Sequence[dict[str, Any]]]
) -> list[dict[str, Any]] | None:
    target = list(event_ids)
    for events in segments:
        segment_ids = [str(event["event_id"]) for event in events]
        for start in range(len(segment_ids) - len(target) + 1):
            if segment_ids[start : start + len(target)] == target:
                return list(events[start : start + len(target)])
    return None


def _validate_candidate_windows(
    baseline: dict[str, Any],
    segments: Sequence[Sequence[dict[str, Any]]],
    selections: Sequence[CandidateWindow],
    threshold: int,
    window_seconds: int,
) -> None:
    candidate_ids: set[str] = set()
    event_sequences: set[tuple[str, ...]] = set()
    declared_selected: set[tuple[str, ...]] = set()
    expected_selected = {candidate.event_ids for candidate in selections}
    for record in baseline["candidate_windows"]:
        candidate_id = str(record.get("candidate_id", ""))
        event_ids = tuple(str(item) for item in record.get("event_ids", []))
        if not candidate_id or candidate_id in candidate_ids:
            raise ValueError("baseline candidate IDs must be non-empty and unique")
        if not event_ids or event_ids in event_sequences:
            raise ValueError("baseline candidate event sequences must be unique")
        candidate_ids.add(candidate_id)
        event_sequences.add(event_ids)
        events = _contiguous_events(event_ids, segments)
        if events is None:
            raise ValueError("baseline candidate must be contiguous inside one segment")
        first_seen = parse_timestamp(str(events[0]["timestamp"]))
        last_seen = parse_timestamp(str(events[-1]["timestamp"]))
        try:
            recorded_first = parse_timestamp(str(record["first_seen"]))
            recorded_last = parse_timestamp(str(record["last_seen"]))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("baseline candidate timestamps are invalid") from error
        if (
            len(event_ids) < threshold
            or (last_seen - first_seen).total_seconds() > window_seconds
            or recorded_first != first_seen
            or recorded_last != last_seen
            or record.get("event_count") != len(event_ids)
            or record.get("threshold_crossing_event_id")
            != event_ids[threshold - 1]
            or record.get("threshold_met") is not True
        ):
            raise ValueError("baseline candidate evidence does not match fixture events")
        decision = record.get("decision")
        if decision == "selected" and event_ids in expected_selected:
            declared_selected.add(event_ids)
        elif decision != "not_selected" or event_ids in expected_selected:
            raise ValueError("baseline candidate decision disagrees with v0.6 selection")
        if not str(record.get("decision_reason", "")):
            raise ValueError("baseline candidate decision requires a reason")
    if declared_selected != expected_selected:
        raise ValueError("baseline selected windows do not match v0.6 selection")


def validate_fixture_baseline(
    fixture: dict[str, Any], baseline: dict[str, Any]
) -> BaselineContext:
    _validate_fixture(fixture)
    rule = fixture["rule"]
    window_seconds = int(rule["window_seconds"])
    threshold = int(rule["threshold"])
    segments = activity_segments(fixture["events"], window_seconds)
    if baseline.get("format") != "loglens.episode_baseline_expected.v1":
        raise ValueError("unsupported baseline format")
    if baseline.get("fixture_id") != fixture.get("fixture_id"):
        raise ValueError("baseline fixture_id does not match the research fixture")
    if baseline.get("rule") != rule_projection(rule):
        raise ValueError("baseline rule does not match the research fixture")
    if baseline.get("algorithm") != BASELINE_ALGORITHM:
        raise ValueError("baseline algorithm contract is stale or unsupported")

    ordered = ordered_events(fixture["events"])
    derived = baseline["derived_input"]
    records = derived["activity_segments"]
    if (
        derived.get("event_count") != len(ordered)
        or derived.get("activity_segment_count") != len(segments)
        or len(records) != len(segments)
    ):
        raise ValueError("baseline activity segment count does not match derived input")
    for index, (events, record) in enumerate(zip(segments, records), start=1):
        event_ids = [str(event["event_id"]) for event in events]
        gaps = [
            (
                parse_timestamp(str(events[position]["timestamp"]))
                - parse_timestamp(str(events[position - 1]["timestamp"]))
            ).total_seconds()
            for position in range(1, len(events))
        ]
        try:
            recorded_first = parse_timestamp(str(record["first_seen"]))
            recorded_last = parse_timestamp(str(record["last_seen"]))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("baseline segment timestamps are invalid") from error
        if (
            record.get("segment_id") != f"segment:{index}"
            or record.get("event_ids") != event_ids
            or recorded_first != parse_timestamp(str(events[0]["timestamp"]))
            or recorded_last != parse_timestamp(str(events[-1]["timestamp"]))
            or record.get("max_adjacent_gap_seconds") != int(max(gaps, default=0))
        ):
            raise ValueError("baseline derived segment does not match fixture events")

    selections = _baseline_selections(segments, threshold, window_seconds)
    _validate_candidate_windows(
        baseline, segments, selections, threshold, window_seconds
    )
    expected_output = baseline["expected_output"]
    expected_findings = _expected_findings(rule, selections)
    if (
        expected_output.get("episode_count") != len(expected_findings)
        or expected_output.get("findings") != expected_findings
    ):
        raise ValueError("baseline findings do not match the v0.6 selection")
    selected_ids = {
        event_id for selection in selections for event_id in selection.event_ids
    }
    excluded_ids = [
        str(event["event_id"])
        for event in ordered
        if str(event["event_id"]) not in selected_ids
    ]
    decisions = expected_output.get("excluded_event_decisions", [])
    if [item.get("event_id") for item in decisions] != excluded_ids or any(
        item.get("decision") != "excluded" or not str(item.get("reason_code", ""))
        for item in decisions
    ):
        raise ValueError("baseline excluded decisions do not partition fixture events")
    return BaselineContext(
        segments=segments,
        selections=selections,
        episode_count=len(expected_findings),
    )
