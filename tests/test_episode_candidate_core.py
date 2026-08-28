import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.episode_candidate_core import (  # noqa: E402
    activity_segments,
    enumerate_candidate_windows,
    minimum_span_threshold_cores,
    selection_has_minimum_core_gap_contrast,
    selection_has_minimum_gap_contrast,
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

    def test_gap_contrast_separates_dense_peaks_from_uniform_background(self) -> None:
        dense_peaks = make_events(
            [0, 30, 60, 90, 120, 660, 1200, 1740, 2280, 2820, 3360, 3390, 3420, 3450, 3480]
        )
        uniform_background = make_events([150 * offset for offset in range(14)])

        for events, expected_ids, expected_contrast in (
            (dense_peaks, ((1, 5), (11, 15)), True),
            (uniform_background, ((1, 5), (10, 14)), False),
        ):
            selected = select_window_separated_candidates(
                enumerate_candidate_windows(events, 5, 600), 600
            )

            self.assertEqual(
                [candidate.event_ids for candidate in selected],
                [
                    tuple(f"line:{index}" for index in range(start, end + 1))
                    for start, end in expected_ids
                ],
            )
            self.assertEqual(
                selection_has_minimum_gap_contrast(events, selected), expected_contrast
            )
            self.assertEqual(
                selection_has_minimum_gap_contrast(
                    list(reversed(events)), list(reversed(selected))
                ),
                expected_contrast,
            )

    def test_gap_contrast_accepts_a_single_selected_episode(self) -> None:
        events = make_events([0, 30, 60, 90, 120])
        selected = select_window_separated_candidates(
            enumerate_candidate_windows(events, 5, 600), 600
        )

        self.assertTrue(selection_has_minimum_gap_contrast(events, selected))

    def test_gap_contrast_is_not_monotone_under_maximal_window_padding(self) -> None:
        dense_cores = make_events(
            [0, 30, 60, 90, 120, 650, 700, 1260, 1290, 1320, 1350, 1380]
        )
        with_padding = make_events(
            [0, 30, 60, 90, 120, 600, 650, 700, 1260, 1290, 1320, 1350, 1380]
        )
        dense_selected = select_window_separated_candidates(
            enumerate_candidate_windows(dense_cores, 5, 600), 600
        )
        padded_selected = select_window_separated_candidates(
            enumerate_candidate_windows(with_padding, 5, 600), 600
        )

        self.assertEqual(len(activity_segments(dense_cores, 600)), 1)
        self.assertEqual(len(activity_segments(with_padding, 600)), 1)
        self.assertEqual(
            [candidate.event_ids for candidate in dense_selected],
            [
                tuple(f"line:{index}" for index in range(1, 6)),
                tuple(f"line:{index}" for index in range(8, 13)),
            ],
        )
        self.assertEqual(
            [candidate.event_ids for candidate in padded_selected],
            [
                tuple(f"line:{index}" for index in range(1, 7)),
                tuple(f"line:{index}" for index in range(9, 14)),
            ],
        )
        self.assertTrue(
            selection_has_minimum_gap_contrast(dense_cores, dense_selected)
        )
        self.assertFalse(
            selection_has_minimum_gap_contrast(with_padding, padded_selected)
        )

    def test_minimum_span_core_is_stable_under_maximal_window_padding(self) -> None:
        without_padding = make_events(
            [0, 30, 60, 90, 120, 650, 700, 1260, 1290, 1320, 1350, 1380]
        )
        with_padding = make_events(
            [0, 30, 60, 90, 120, 600, 650, 700, 1260, 1290, 1320, 1350, 1380]
        )
        selected_without_padding = select_window_separated_candidates(
            enumerate_candidate_windows(without_padding, 5, 600), 600
        )
        selected_with_padding = select_window_separated_candidates(
            enumerate_candidate_windows(with_padding, 5, 600), 600
        )

        cores_without_padding = minimum_span_threshold_cores(
            without_padding, selected_without_padding, 5
        )
        cores_with_padding = minimum_span_threshold_cores(
            with_padding, selected_with_padding, 5
        )

        self.assertEqual(
            [core.event_ids for core in cores_without_padding],
            [
                tuple(f"line:{index}" for index in range(1, 6)),
                tuple(f"line:{index}" for index in range(8, 13)),
            ],
        )
        self.assertEqual(
            [core.event_ids for core in cores_with_padding],
            [
                tuple(f"line:{index}" for index in range(1, 6)),
                tuple(f"line:{index}" for index in range(9, 14)),
            ],
        )
        self.assertEqual([core.span_seconds for core in cores_with_padding], [120, 120])
        self.assertTrue(
            selection_has_minimum_core_gap_contrast(
                without_padding, selected_without_padding, 5
            )
        )
        self.assertTrue(
            selection_has_minimum_core_gap_contrast(
                with_padding, selected_with_padding, 5
            )
        )
        self.assertEqual(
            minimum_span_threshold_cores(
                list(reversed(with_padding)),
                list(reversed(selected_with_padding)),
                5,
            ),
            cores_with_padding,
        )

    def test_minimum_span_core_preserves_positive_and_uniform_controls(self) -> None:
        dense_peaks = make_events(
            [0, 30, 60, 90, 120, 660, 1200, 1740, 2280, 2820, 3360, 3390, 3420, 3450, 3480]
        )
        uniform_background = make_events([150 * offset for offset in range(14)])

        for events, expected_contrast in (
            (dense_peaks, True),
            (uniform_background, False),
        ):
            selected = select_window_separated_candidates(
                enumerate_candidate_windows(events, 5, 600), 600
            )

            self.assertEqual(
                selection_has_minimum_core_gap_contrast(events, selected, 5),
                expected_contrast,
            )
            self.assertEqual(
                selection_has_minimum_core_gap_contrast(
                    list(reversed(events)), list(reversed(selected)), 5
                ),
                expected_contrast,
            )

    def test_minimum_span_core_breaks_ties_chronologically(self) -> None:
        events = make_events([0, 1, 2, 3, 4, 5])
        selected = select_window_separated_candidates(
            enumerate_candidate_windows(events, 5, 600), 600
        )

        cores = minimum_span_threshold_cores(events, selected, 5)

        self.assertEqual(
            [core.event_ids for core in cores],
            [tuple(f"line:{index}" for index in range(1, 6))],
        )
        for invalid_threshold in (True, 1, 7):
            with self.assertRaisesRegex(ValueError, "threshold"):
                minimum_span_threshold_cores(events, selected, invalid_threshold)

    def test_gap_contrast_requires_a_positive_ratio(self) -> None:
        with self.assertRaisesRegex(ValueError, "minimum_ratio"):
            selection_has_minimum_gap_contrast([], [], minimum_ratio=0)

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
