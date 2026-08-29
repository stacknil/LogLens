import copy
import json
import sys
import unittest
from datetime import timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_episode_candidate import (  # noqa: E402
    ALGORITHM_V2,
    evaluate_fixture,
    materialize_core_contrast_admission,
    validate_oracle,
)
from scripts.episode_candidate_core import (  # noqa: E402
    enumerate_candidate_windows,
    parse_timestamp,
    select_window_separated_candidates,
)


FIXTURE_ROOT = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "episode_semantics_v0.7"
    / "continuous_background_two_peaks"
)
ISOLATED_FIXTURE_ROOT = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "episode_semantics_v0.7"
    / "isolated_dense_bursts"
)


class ContinuousBackgroundFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(
            (FIXTURE_ROOT / "fixture.json").read_text(encoding="utf-8")
        )
        self.baseline = json.loads(
            (FIXTURE_ROOT / "baseline.expected.json").read_text(encoding="utf-8")
        )

    def test_candidate_recovers_two_peaks_without_reusing_events(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        segment = oracle["segments"][0]

        self.assertEqual(oracle["comparison"]["baseline_episode_count"], 1)
        self.assertEqual(oracle["comparison"]["candidate_episode_count"], 2)
        self.assertEqual(
            [episode["finding_id"] for episode in segment["selected_episodes"]],
            [
                "finding:brute_force:584fd14b544a7959",
                "finding:brute_force:a885dcb623777120",
            ],
        )
        included = [
            decision["event_id"]
            for decision in segment["event_decisions"]
            if decision["decision"] == "included"
        ]
        self.assertEqual(
            included,
            [f"line:{i}" for i in range(1, 6)] + [f"line:{i}" for i in range(11, 16)],
        )
        self.assertEqual(len(included), len(set(included)))

    def test_input_permutation_does_not_change_oracle(self) -> None:
        shuffled = copy.deepcopy(self.fixture)
        shuffled["events"].reverse()

        self.assertEqual(
            evaluate_fixture(shuffled, self.baseline),
            evaluate_fixture(self.fixture, self.baseline),
        )

    def test_generated_oracle_matches_committed_fixture_and_cross_references(
        self,
    ) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        expected = json.loads(
            (FIXTURE_ROOT / "candidate.window-separated-v1.expected.json").read_text(
                encoding="utf-8"
            )
        )

        validate_oracle(self.fixture, self.baseline, oracle)
        self.assertEqual(oracle, expected)

    def test_validator_rejects_duplicate_event_decisions(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        oracle["segments"][0]["event_decisions"].append(
            copy.deepcopy(oracle["segments"][0]["event_decisions"][0])
        )

        with self.assertRaisesRegex(ValueError, "exactly one event decision"):
            validate_oracle(self.fixture, self.baseline, oracle)

    def test_validator_rejects_fixture_inconsistent_derived_fields(self) -> None:
        mutations = {
            "segment identity": lambda oracle: oracle["segments"][0].__setitem__(
                "segment_id", "segment:tampered"
            ),
            "candidate score": lambda oracle: oracle["segments"][0][
                "candidate_windows"
            ][0]["score"]["details"].__setitem__("span_seconds", 999),
            "comparison": lambda oracle: oracle["comparison"].__setitem__(
                "continuous_segment_split", False
            ),
        }

        for label, mutate in mutations.items():
            with self.subTest(label=label):
                oracle = evaluate_fixture(self.fixture, self.baseline)
                mutate(oracle)
                with self.assertRaisesRegex(ValueError, "canonical fixture derivation"):
                    validate_oracle(self.fixture, self.baseline, oracle)

    def test_equivalent_timezone_offsets_produce_the_same_oracle(self) -> None:
        offset_fixture = copy.deepcopy(self.fixture)
        offset = timezone(timedelta(hours=1))
        for event in offset_fixture["events"]:
            event["timestamp"] = parse_timestamp(event["timestamp"]).astimezone(
                offset
            ).isoformat()

        self.assertEqual(
            evaluate_fixture(offset_fixture, self.baseline),
            evaluate_fixture(self.fixture, self.baseline),
        )

    def test_v2_materializes_core_contrast_admission_without_changing_selection(
        self,
    ) -> None:
        v1 = evaluate_fixture(self.fixture, self.baseline)
        v2 = evaluate_fixture(
            self.fixture, self.baseline, algorithm=ALGORITHM_V2
        )
        admission = v2["segments"][0]["admission"]

        self.assertEqual(v2["format"], "loglens.episode_candidate_oracle.v2")
        self.assertEqual(
            v2["algorithm"],
            {
                "id": "research.window_separated_minimum_core_contrast",
                "version": "2",
                "status": "candidate",
            },
        )
        self.assertEqual(
            v2["segments"][0]["selected_episodes"],
            v1["segments"][0]["selected_episodes"],
        )
        self.assertEqual(
            [core["event_ids"] for core in admission["threshold_cores"]],
            [
                [f"line:{index}" for index in range(1, 6)],
                [f"line:{index}" for index in range(11, 16)],
            ],
        )
        self.assertEqual(
            [core["mean_gap_microseconds"] for core in admission["threshold_cores"]],
            [
                {"numerator": 30_000_000, "denominator": 1},
                {"numerator": 30_000_000, "denominator": 1},
            ],
        )
        self.assertEqual(
            admission["adjacent_contrasts"],
            [
                {
                    "left_candidate_id": "candidate:line:1..line:5",
                    "right_candidate_id": "candidate:line:11..line:15",
                    "bridge_event_ids": [f"line:{index}" for index in range(6, 11)],
                    "bridge_mean_gap_microseconds": {
                        "numerator": 540_000_000,
                        "denominator": 1,
                    },
                    "required_bridge_mean_gap_microseconds": {
                        "numerator": 60_000_000,
                        "denominator": 1,
                    },
                    "passes": True,
                    "reason_code": "minimum_core_gap_contrast_met",
                }
            ],
        )
        self.assertTrue(admission["admitted"])
        self.assertEqual(
            admission["reason_code"], "all_adjacent_core_contrasts_met"
        )
        validate_oracle(
            self.fixture, self.baseline, v2, algorithm=ALGORITHM_V2
        )

    def test_v2_materializes_uniform_background_rejection_without_hiding_selection(
        self,
    ) -> None:
        origin = parse_timestamp("2026-03-10T09:00:00Z")
        events = [
            {
                "event_id": f"line:{index}",
                "line_number": index,
                "timestamp": (origin + timedelta(seconds=150 * (index - 1)))
                .isoformat()
                .replace("+00:00", "Z"),
                "event_type": "ssh_failed_password",
                "source_ip": "203.0.113.77",
            }
            for index in range(1, 15)
        ]
        selected = select_window_separated_candidates(
            enumerate_candidate_windows(events, 5, 600), 600
        )

        admission = materialize_core_contrast_admission(events, selected, 5)

        self.assertEqual(len(selected), 2)
        self.assertFalse(admission["admitted"])
        self.assertEqual(
            admission["reason_code"], "adjacent_core_contrast_below_minimum"
        )
        self.assertEqual(
            admission["adjacent_contrasts"][0]["reason_code"],
            "minimum_core_gap_contrast_below_minimum",
        )
        self.assertFalse(admission["adjacent_contrasts"][0]["passes"])


class IsolatedDenseBurstsFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(
            (ISOLATED_FIXTURE_ROOT / "fixture.json").read_text(encoding="utf-8")
        )
        self.baseline = json.loads(
            (ISOLATED_FIXTURE_ROOT / "baseline.expected.json").read_text(
                encoding="utf-8"
            )
        )

    def test_candidate_preserves_already_separated_baseline(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        baseline_finding_ids = [
            finding["finding_id"]
            for finding in self.baseline["expected_output"]["findings"]
        ]
        candidate_finding_ids = [
            episode["finding_id"]
            for segment in oracle["segments"]
            for episode in segment["selected_episodes"]
        ]
        included_event_ids = [
            decision["event_id"]
            for segment in oracle["segments"]
            for decision in segment["event_decisions"]
            if decision["decision"] == "included"
        ]

        self.assertEqual(oracle["comparison"]["baseline_episode_count"], 2)
        self.assertEqual(oracle["comparison"]["candidate_episode_count"], 2)
        self.assertFalse(oracle["comparison"]["continuous_segment_split"])
        self.assertEqual(candidate_finding_ids, baseline_finding_ids)
        self.assertEqual(included_event_ids, [f"line:{i}" for i in range(1, 11)])
        self.assertEqual(len(included_event_ids), len(set(included_event_ids)))

    def test_input_representation_does_not_change_control_oracle(self) -> None:
        expected = evaluate_fixture(self.fixture, self.baseline)
        variants = {
            "reversed": copy.deepcopy(self.fixture),
            "equivalent timezone": copy.deepcopy(self.fixture),
        }
        variants["reversed"]["events"].reverse()
        offset = timezone(timedelta(hours=-5))
        for event in variants["equivalent timezone"]["events"]:
            event["timestamp"] = parse_timestamp(event["timestamp"]).astimezone(
                offset
            ).isoformat()

        for label, fixture in variants.items():
            with self.subTest(label=label):
                self.assertEqual(evaluate_fixture(fixture, self.baseline), expected)

    def test_generated_oracle_matches_committed_control_and_cross_references(
        self,
    ) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        expected = json.loads(
            (
                ISOLATED_FIXTURE_ROOT
                / "candidate.window-separated-v1.expected.json"
            ).read_text(encoding="utf-8")
        )

        validate_oracle(self.fixture, self.baseline, oracle)
        self.assertEqual(oracle, expected)

if __name__ == "__main__":
    unittest.main()
