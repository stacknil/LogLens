import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.episode_candidate_core import (  # noqa: E402
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

    def test_overlapping_candidates_materialize_one_maximal_window(self) -> None:
        candidates = enumerate_candidate_windows(
            make_events([0, 1, 2, 3, 4, 5]), 5, 600
        )
        selected = select_window_separated_candidates(candidates, 600)

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].event_ids, tuple(f"line:{i}" for i in range(1, 7)))

    def test_research_size_limits_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "at most 200 events"):
            enumerate_candidate_windows(make_events(list(range(201))), 5, 600)
        with self.assertRaisesRegex(ValueError, "candidate limit exceeded"):
            enumerate_candidate_windows(make_events(list(range(50))), 5, 600)


if __name__ == "__main__":
    unittest.main()
