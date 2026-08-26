#!/usr/bin/env python3
"""Evaluate a research-only episode candidate against committed fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

if __package__:
    from .episode_baseline_contract import (
        canonical_oracle_timestamp,
        finding_id,
        rule_projection,
        validate_fixture_baseline,
    )
    from .episode_candidate_core import (
        CandidateWindow,
        enumerate_candidate_windows,
        ordered_events,
        parse_timestamp,
        select_window_separated_candidates,
    )
else:
    from episode_baseline_contract import (
        canonical_oracle_timestamp,
        finding_id,
        rule_projection,
        validate_fixture_baseline,
    )
    from episode_candidate_core import (
        CandidateWindow,
        enumerate_candidate_windows,
        ordered_events,
        parse_timestamp,
        select_window_separated_candidates,
    )

def _candidate_membership_index(
    records: Iterable[tuple[str, Sequence[str]]],
) -> dict[str, tuple[str, ...]]:
    memberships: dict[str, list[str]] = {}
    for candidate_id, event_ids in records:
        for event_id in event_ids:
            memberships.setdefault(str(event_id), []).append(str(candidate_id))
    return {
        event_id: tuple(sorted(candidate_ids))
        for event_id, candidate_ids in memberships.items()
    }


def _candidate_json(
    candidate: CandidateWindow,
    memberships: dict[str, tuple[str, ...]],
    selected_ids: set[str],
) -> dict[str, Any]:
    overlaps = sorted(
        event_id
        for event_id in candidate.event_ids
        if len(memberships.get(event_id, ())) > 1
    )
    selected = candidate.candidate_id in selected_ids
    return {
        "candidate_id": candidate.candidate_id,
        "event_ids": list(candidate.event_ids),
        "first_seen": canonical_oracle_timestamp(candidate.first_seen),
        "last_seen": canonical_oracle_timestamp(candidate.last_seen),
        "threshold_crossing_event_ids": [candidate.threshold_crossing_event_id],
        "overlap_event_ids": overlaps,
        "score": {
            "metric": "event_count_then_compactness",
            "value": candidate.event_count,
            "details": {
                "event_count": candidate.event_count,
                "span_seconds": candidate.span_seconds,
            },
        },
        "decision": {
            "selected": selected,
            "reason_code": "selected" if selected else "not_selected",
            "reason": (
                "Selected by maximum covered events, then minimum total span and episode count."
                if selected
                else "Rejected by overlap/cooldown compatibility or the deterministic global objective."
            ),
        },
    }


def _validate_baseline_reference(baseline_reference: str) -> None:
    if (
        not baseline_reference
        or "/" in baseline_reference
        or "\\" in baseline_reference
    ):
        raise ValueError("baseline_reference must be a privacy-safe file name")


def _build_oracle(
    fixture: dict[str, Any],
    segments: Sequence[Sequence[dict[str, Any]]],
    baseline_episode_count: int,
    baseline_reference: str,
) -> dict[str, Any]:
    rule = fixture["rule"]
    window_seconds = int(rule["window_seconds"])
    threshold = int(rule["threshold"])
    output_segments: list[dict[str, Any]] = []
    episode_index = 0

    for segment_number, events in enumerate(segments, start=1):
        segment_id = f"segment:{segment_number}"
        event_ids = [str(event["event_id"]) for event in events]
        candidates = enumerate_candidate_windows(events, threshold, window_seconds)
        selected = select_window_separated_candidates(candidates, window_seconds)
        selected_ids = {candidate.candidate_id for candidate in selected}
        memberships = _candidate_membership_index(
            (candidate.candidate_id, candidate.event_ids) for candidate in candidates
        )
        selected_event_ids = {
            event_id for candidate in selected for event_id in candidate.event_ids
        }
        episodes = []
        for candidate in selected:
            episode_index += 1
            episodes.append(
                {
                    "episode_index": episode_index,
                    "finding_id": finding_id(rule, candidate),
                    "candidate_id": candidate.candidate_id,
                    "event_ids": list(candidate.event_ids),
                    "first_seen": canonical_oracle_timestamp(candidate.first_seen),
                    "last_seen": canonical_oracle_timestamp(candidate.last_seen),
                    "inclusion_reason": "Window is part of the optimal window-separated evidence set.",
                }
            )
        event_decisions = []
        for event in events:
            event_id = str(event["event_id"])
            containing = list(memberships.get(event_id, ()))
            included = event_id in selected_event_ids
            event_decisions.append(
                {
                    "event_id": event_id,
                    "decision": "included" if included else "excluded",
                    "reason_code": "selected_window"
                    if included
                    else (
                        "bridge_background"
                        if event.get("role") == "bridge_background"
                        else "not_selected"
                    ),
                    "candidate_ids": containing,
                    "reason": (
                        "Included exactly once by a selected candidate window."
                        if included
                        else "Retained as background evidence outside every selected dense window."
                    ),
                }
            )
        output_segments.append(
            {
                "segment_id": segment_id,
                "event_ids": event_ids,
                "first_seen": canonical_oracle_timestamp(
                    parse_timestamp(str(events[0]["timestamp"]))
                ),
                "last_seen": canonical_oracle_timestamp(
                    parse_timestamp(str(events[-1]["timestamp"]))
                ),
                "candidate_windows": [
                    _candidate_json(candidate, memberships, selected_ids)
                    for candidate in candidates
                ],
                "selected_episodes": episodes,
                "event_decisions": event_decisions,
            }
        )

    oracle = {
        "format": "loglens.episode_candidate_oracle.v1",
        "fixture_id": fixture["fixture_id"],
        "algorithm": {
            "id": "research.window_separated_weighted_intervals",
            "version": "1",
            "status": "candidate",
        },
        "rule": rule_projection(rule),
        "segments": output_segments,
        "comparison": {
            "baseline_reference": baseline_reference,
            "baseline_episode_count": baseline_episode_count,
            "candidate_episode_count": episode_index,
            "continuous_segment_split": episode_index > baseline_episode_count,
            "notes": [
                "Research-only candidate; Detector::analyze() and loglens.report.v3 are unchanged.",
                "Selected windows require a gap strictly greater than one rule window; exact-boundary gaps remain one cooldown episode.",
                "Selection maximizes covered evidence count, then minimizes total span and episode count, with a chronological final tie-break.",
                "Exhaustive candidate materialization and overlap reporting have super-quadratic worst-case cost; hard limits keep this fixture tool bounded, not production-ready.",
            ],
        },
    }
    return oracle


def evaluate_fixture(
    fixture: dict[str, Any],
    baseline: dict[str, Any],
    baseline_reference: str = "baseline.expected.json",
) -> dict[str, Any]:
    _validate_baseline_reference(baseline_reference)
    context = validate_fixture_baseline(fixture, baseline)
    oracle = _build_oracle(
        fixture, context.segments, context.episode_count, baseline_reference
    )
    _validate_oracle_cross_references(fixture, oracle)
    return oracle


def _validate_oracle_cross_references(
    fixture: dict[str, Any], oracle: dict[str, Any]
) -> None:
    if oracle.get("fixture_id") != fixture.get("fixture_id"):
        raise ValueError("oracle fixture_id must match the research fixture")
    if oracle.get("rule") != rule_projection(fixture["rule"]):
        raise ValueError("oracle rule must match the research fixture")

    fixture_ids = [
        str(event["event_id"]) for event in ordered_events(fixture["events"])
    ]
    segment_ids: list[str] = []
    selected_count = 0
    episode_indexes: list[int] = []
    for segment in oracle["segments"]:
        events = list(segment["event_ids"])
        segment_ids.extend(events)
        decisions = [decision["event_id"] for decision in segment["event_decisions"]]
        if len(decisions) != len(set(decisions)) or set(decisions) != set(events):
            raise ValueError(
                "exactly one event decision is required for every segment event"
            )
        candidate_records = segment["candidate_windows"]
        candidate_ids = [candidate["candidate_id"] for candidate in candidate_records]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate IDs must be unique inside a segment")
        candidates = {
            candidate["candidate_id"]: candidate for candidate in candidate_records
        }
        for candidate in candidate_records:
            if not set(candidate["event_ids"]).issubset(events):
                raise ValueError(
                    "candidate evidence must stay inside its baseline segment"
                )
        memberships = _candidate_membership_index(
            (candidate_id, candidate["event_ids"])
            for candidate_id, candidate in candidates.items()
        )
        selected_candidate_ids = {
            candidate_id
            for candidate_id, candidate in candidates.items()
            if candidate["decision"]["selected"]
        }
        selected_events: set[str] = set()
        episode_candidate_ids: list[str] = []
        episode_order: list[tuple[datetime, datetime, str]] = []
        for episode in segment["selected_episodes"]:
            candidate_id = episode["candidate_id"]
            if (
                candidate_id not in candidates
                or not candidates[candidate_id]["decision"]["selected"]
            ):
                raise ValueError("selected episode must reference a selected candidate")
            candidate = candidates[candidate_id]
            if (
                episode["event_ids"] != candidate["event_ids"]
                or episode["first_seen"] != candidate["first_seen"]
                or episode["last_seen"] != candidate["last_seen"]
            ):
                raise ValueError("selected episode evidence must match its candidate")
            materialized = CandidateWindow(
                event_ids=tuple(candidate["event_ids"]),
                first_seen=parse_timestamp(candidate["first_seen"]),
                last_seen=parse_timestamp(candidate["last_seen"]),
                threshold_crossing_event_id="",
            )
            if episode["finding_id"] != finding_id(fixture["rule"], materialized):
                raise ValueError(
                    "selected episode finding_id must match its candidate evidence"
                )
            overlap = selected_events.intersection(episode["event_ids"])
            if overlap:
                raise ValueError("selected episodes reuse event evidence")
            selected_events.update(episode["event_ids"])
            selected_count += 1
            episode_indexes.append(int(episode["episode_index"]))
            episode_candidate_ids.append(candidate_id)
            episode_order.append(
                (materialized.first_seen, materialized.last_seen, candidate_id)
            )
        if len(episode_candidate_ids) != len(set(episode_candidate_ids)):
            raise ValueError("a candidate may materialize at most one selected episode")
        if set(episode_candidate_ids) != selected_candidate_ids:
            raise ValueError(
                "selected candidates and materialized episodes must match exactly"
            )
        if episode_order != sorted(episode_order):
            raise ValueError("selected episodes must be chronological")
        included = {
            decision["event_id"]
            for decision in segment["event_decisions"]
            if decision["decision"] == "included"
        }
        if included != selected_events:
            raise ValueError(
                "included event decisions must equal selected episode evidence"
            )
        for decision in segment["event_decisions"]:
            expected_candidates = list(memberships.get(decision["event_id"], ()))
            if decision.get("candidate_ids", []) != expected_candidates:
                raise ValueError(
                    "event decision candidate_ids must match candidate evidence"
                )
    if segment_ids != fixture_ids or len(segment_ids) != len(set(segment_ids)):
        raise ValueError("oracle segments must partition fixture events exactly once")
    if episode_indexes != list(range(1, selected_count + 1)):
        raise ValueError("episode indexes must be chronological and contiguous")
    if oracle["comparison"]["candidate_episode_count"] != selected_count:
        raise ValueError("comparison candidate count must match selected episodes")


def validate_oracle(
    fixture: dict[str, Any],
    baseline: dict[str, Any],
    oracle: dict[str, Any],
    baseline_reference: str = "baseline.expected.json",
) -> None:
    _validate_baseline_reference(baseline_reference)
    context = validate_fixture_baseline(fixture, baseline)
    _validate_oracle_cross_references(fixture, oracle)
    expected = _build_oracle(
        fixture, context.segments, context.episode_count, baseline_reference
    )
    if oracle != expected:
        raise ValueError("oracle does not match the canonical fixture derivation")


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument(
        "--check",
        type=Path,
        help="Require generated JSON to match this committed oracle.",
    )
    parser.add_argument(
        "--output", type=Path, help="Write generated JSON; otherwise print it."
    )
    args = parser.parse_args(argv)

    try:
        oracle = evaluate_fixture(
            _load(args.fixture),
            _load(args.baseline),
            baseline_reference=args.baseline.name,
        )
        rendered = json.dumps(oracle, indent=2, ensure_ascii=False) + "\n"
        if (
            args.check is not None
            and args.check.read_text(encoding="utf-8") != rendered
        ):
            print(f"candidate oracle drift: {args.check.name}", file=sys.stderr)
            return 1
        if args.output is not None:
            args.output.write_text(rendered, encoding="utf-8", newline="\n")
        elif args.check is None:
            sys.stdout.write(rendered)
        return 0
    except json.JSONDecodeError as error:
        print(
            f"episode candidate error: invalid JSON at line {error.lineno}, column {error.colno}",
            file=sys.stderr,
        )
    except OSError as error:
        print(
            f"episode candidate error: I/O failure ({error.strerror or 'operation failed'})",
            file=sys.stderr,
        )
    except (KeyError, TypeError, ValueError):
        print(
            "episode candidate error: invalid fixture, baseline, or oracle data",
            file=sys.stderr,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
