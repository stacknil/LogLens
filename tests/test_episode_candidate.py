import copy
import json
import sys
import unittest
from datetime import timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_episode_candidate import (  # noqa: E402
    evaluate_fixture,
    validate_oracle,
)
from scripts.episode_candidate_core import parse_timestamp  # noqa: E402


FIXTURE_ROOT = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "episode_semantics_v0.7"
    / "continuous_background_two_peaks"
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

if __name__ == "__main__":
    unittest.main()
