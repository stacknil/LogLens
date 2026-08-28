import copy
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ModuleNotFoundError:  # The evaluator itself remains standard-library only.
    Draft202012Validator = None
    FormatChecker = None


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_episode_candidate import (  # noqa: E402
    ALGORITHM_V2,
    evaluate_fixture,
    main,
    validate_oracle,
)


FIXTURE_ROOT = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "episode_semantics_v0.7"
    / "continuous_background_two_peaks"
)
CANDIDATE_ORACLES = (
    FIXTURE_ROOT / "candidate.window-separated-v1.expected.json",
    FIXTURE_ROOT / "candidate.window-separated-core-contrast-v2.expected.json",
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "episode_semantics_v0.7"
    / "isolated_dense_bursts"
    / "candidate.window-separated-v1.expected.json",
)


class CandidateOracleValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(
            (FIXTURE_ROOT / "fixture.json").read_text(encoding="utf-8")
        )
        self.baseline = json.loads(
            (FIXTURE_ROOT / "baseline.expected.json").read_text(encoding="utf-8")
        )

    @unittest.skipIf(
        Draft202012Validator is None,
        "install requirements-test.txt to validate the JSON Schema",
    )
    def test_committed_oracles_conform_to_draft_2020_12_schema(self) -> None:
        schema = json.loads(
            (FIXTURE_ROOT / "candidate-oracle.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for path in CANDIDATE_ORACLES:
            with self.subTest(oracle=path.name):
                oracle = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(list(validator.iter_errors(oracle)), [])

    @unittest.skipIf(
        Draft202012Validator is None,
        "install requirements-test.txt to validate the JSON Schema",
    )
    def test_schema_rejects_cross_version_algorithm_and_admission_shapes(
        self,
    ) -> None:
        schema = json.loads(
            (FIXTURE_ROOT / "candidate-oracle.schema.json").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        v1 = json.loads(CANDIDATE_ORACLES[0].read_text(encoding="utf-8"))
        v2 = json.loads(CANDIDATE_ORACLES[1].read_text(encoding="utf-8"))
        v1_with_admission = copy.deepcopy(v1)
        v1_with_admission["segments"][0]["admission"] = copy.deepcopy(
            v2["segments"][0]["admission"]
        )
        v2_without_admission = copy.deepcopy(v2)
        del v2_without_admission["segments"][0]["admission"]
        v2_with_v1_algorithm = copy.deepcopy(v2)
        v2_with_v1_algorithm["algorithm"] = copy.deepcopy(v1["algorithm"])

        for label, oracle in (
            ("v1 with admission", v1_with_admission),
            ("v2 without admission", v2_without_admission),
            ("v2 with v1 algorithm", v2_with_v1_algorithm),
        ):
            with self.subTest(label=label):
                self.assertNotEqual(list(validator.iter_errors(oracle)), [])

    def test_validator_rejects_episode_evidence_drift(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        oracle["segments"][0]["selected_episodes"][0]["event_ids"].pop()

        with self.assertRaisesRegex(ValueError, "episode evidence"):
            validate_oracle(self.fixture, self.baseline, oracle)

    def test_validator_rejects_selected_candidate_without_episode(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        oracle["segments"][0]["selected_episodes"].pop()

        with self.assertRaisesRegex(ValueError, "selected candidates"):
            validate_oracle(self.fixture, self.baseline, oracle)

    def test_validator_rejects_selected_episodes_that_reuse_event_evidence(
        self,
    ) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        segment = oracle["segments"][0]
        first_episode, second_episode = segment["selected_episodes"]
        candidates = {
            candidate["candidate_id"]: candidate
            for candidate in segment["candidate_windows"]
        }
        first_candidate = candidates[first_episode["candidate_id"]]
        second_candidate = candidates[second_episode["candidate_id"]]
        for field in ("event_ids", "first_seen", "last_seen"):
            second_candidate[field] = copy.deepcopy(first_candidate[field])
            second_episode[field] = copy.deepcopy(first_episode[field])
        second_episode["finding_id"] = first_episode["finding_id"]

        with self.assertRaisesRegex(ValueError, "reuse event evidence"):
            validate_oracle(self.fixture, self.baseline, oracle)

    def test_validator_rejects_event_candidate_reference_drift(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        oracle["segments"][0]["event_decisions"][0]["candidate_ids"] = []

        with self.assertRaisesRegex(ValueError, "candidate_ids"):
            validate_oracle(self.fixture, self.baseline, oracle)

    def test_input_pair_fails_closed_on_boundary_or_baseline_drift(self) -> None:
        exclusive = copy.deepcopy(self.fixture)
        exclusive["rule"]["window_boundary"] = "exclusive"
        with self.assertRaisesRegex(ValueError, "candidate v1 supports only"):
            evaluate_fixture(exclusive, self.baseline)

        stale_baseline = copy.deepcopy(self.baseline)
        stale_baseline["fixture_id"] = "another-fixture"
        with self.assertRaisesRegex(ValueError, "fixture_id"):
            evaluate_fixture(self.fixture, stale_baseline)

    def test_cli_returns_two_without_disclosing_invalid_input_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            malformed = Path(directory) / "fixture.json"
            malformed.write_text("{", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                status = main(
                    [
                        "--fixture",
                        str(malformed),
                        "--baseline",
                        str(FIXTURE_ROOT / "baseline.expected.json"),
                    ]
                )

            self.assertEqual(status, 2)
            self.assertIn("invalid JSON", stderr.getvalue())
            self.assertNotIn(directory, stderr.getvalue())

    def test_unknown_algorithm_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported candidate algorithm"):
            evaluate_fixture(self.fixture, self.baseline, algorithm="unknown")

    def test_v2_validator_rejects_admission_drift(self) -> None:
        oracle = evaluate_fixture(
            self.fixture, self.baseline, algorithm=ALGORITHM_V2
        )
        oracle["segments"][0]["admission"]["admitted"] = False

        with self.assertRaisesRegex(ValueError, "canonical fixture derivation"):
            validate_oracle(
                self.fixture, self.baseline, oracle, algorithm=ALGORITHM_V2
            )


if __name__ == "__main__":
    unittest.main()
