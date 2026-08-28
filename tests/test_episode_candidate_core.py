import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.episode_candidate_core import (  # noqa: E402
    activity_segments,
    enumerate_candidate_windows,
    select_window_separated_candidates,
)


def make_events(offsets: list[int]) -> list[dict[str, object]]:
    origin = datetime(2026, 3, 10, 9, 0, tzinfo=timezone.utc)
    return [
        {
            "event_id": f"line:{index}",
            "line_number": index,
            "timestamp": (origin + timedelta(seconds=offset))
            .isoformat()
            .replace("+00:00", "Z"),
            "event_type": "ssh_failed_password",
            "source_ip": "203.0.113.77",
        }
        for index, offset in enumerate(offsets, start=1)
    ]


class WindowSeparatedSelectionTests(unittest.TestCase):
    def test_threshold_and_window_boundaries_are_inclusive(self) -> None:
        exact = make_events([0, 597, 598, 599, 600])
        below = exact[:-1]

        self.assertEqual(len(enumerate_candidate_windows(exact, 5, 600)), 1)
        self.assertEqual(enumerate_candidate_windows(below, 5, 600), [])

    def test_candidate_cooldown_requires_more_than_one_rule_window(self) -> None:
        exact_gap = make_events([0, 1, 2, 3, 4, 604, 605, 606, 607, 608])
        over_gap = make_events([0, 1, 2, 3, 4, 605, 606, 607, 608, 609])

        exact_selected = select_window_separated_candidates(
            enumerate_candidate_windows(exact_gap, 5, 600), 600
        )
        over_selected = select_window_separated_candidates(
            enumerate_candidate_windows(over_gap, 5, 600), 600
        )

        self.assertEqual(
            [candidate.event_ids for candidate in exact_selected],
            [tuple(f"line:{i}" for i in range(1, 6))],
        )
        self.assertEqual(
            [candidate.event_ids for candidate in over_selected],
            [
                tuple(f"line:{i}" for i in range(1, 6)),
                tuple(f"line:{i}" for i in range(6, 11)),
            ],
        )

    def test_shared_evidence_is_search_membership_not_double_consumption(self) -> None:
        candidates = enumerate_candidate_windows(
            make_events([0, 1, 2, 3, 4, 5]), 5, 600
        )
        selected = select_window_separated_candidates(candidates, 600)
        materialized_event_ids = [
            event_id for candidate in selected for event_id in candidate.event_ids
        ]

        self.assertEqual(
            [candidate.event_ids for candidate in candidates],
            [
                tuple(f"line:{i}" for i in range(1, 6)),
                tuple(f"line:{i}" for i in range(1, 7)),
                tuple(f"line:{i}" for i in range(2, 7)),
            ],
        )
        self.assertEqual(
            set.intersection(*(set(candidate.event_ids) for candidate in candidates)),
            {f"line:{i}" for i in range(2, 6)},
        )
        self.assertEqual(materialized_event_ids, [f"line:{i}" for i in range(1, 7)])
        self.assertEqual(len(materialized_event_ids), len(set(materialized_event_ids)))

    def test_uniform_threshold_rate_can_multiply_episodes_in_one_segment(self) -> None:
        thirteen_events = make_events([150 * offset for offset in range(13)])
        fourteen_events = make_events([150 * offset for offset in range(14)])
        thirteen_selected = select_window_separated_candidates(
            enumerate_candidate_windows(thirteen_events, 5, 600), 600
        )
        fourteen_selected = select_window_separated_candidates(
            enumerate_candidate_windows(fourteen_events, 5, 600), 600
        )

        self.assertEqual(len(activity_segments(fourteen_events, 600)), 1)
        self.assertEqual(
            [candidate.event_ids for candidate in thirteen_selected],
            [tuple(f"line:{i}" for i in range(1, 6))],
        )
        self.assertEqual(
            [candidate.event_ids for candidate in fourteen_selected],
            [
                tuple(f"line:{i}" for i in range(1, 6)),
                tuple(f"line:{i}" for i in range(10, 15)),
            ],
        )

    def test_equal_score_windows_prefer_chronological_key(self) -> None:
        candidates = enumerate_candidate_windows(
            make_events([0, 1, 2, 3, 600, 601]), 5, 600
        )
        expected = [tuple(f"line:{i}" for i in range(1, 6))]

        self.assertEqual(
            [candidate.event_ids for candidate in candidates],
            [
                tuple(f"line:{i}" for i in range(1, 6)),
                tuple(f"line:{i}" for i in range(2, 7)),
            ],
        )
        for ordered_candidates in (candidates, list(reversed(candidates))):
            selected = select_window_separated_candidates(ordered_candidates, 600)

            self.assertEqual(
                [candidate.event_ids for candidate in selected], expected
            )

    def test_research_size_limits_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "at most 200 events"):
            enumerate_candidate_windows(make_events(list(range(201))), 5, 600)
        with self.assertRaisesRegex(ValueError, "candidate limit exceeded"):
            enumerate_candidate_windows(make_events(list(range(50))), 5, 600)


if __name__ == "__main__":
    unittest.main()
