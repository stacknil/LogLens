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
    def test_committed_oracle_conforms_to_draft_2020_12_schema(self) -> None:
        schema = json.loads(
            (FIXTURE_ROOT / "candidate-oracle.schema.json").read_text(encoding="utf-8")
        )
        oracle = json.loads(
            (FIXTURE_ROOT / "candidate.window-separated-v1.expected.json").read_text(
                encoding="utf-8"
            )
        )

        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(oracle)), [])

    def test_validator_rejects_episode_evidence_drift(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        oracle["segments"][0]["selected_episodes"][0]["event_ids"].pop()

        with self.assertRaisesRegex(ValueError, "episode evidence"):
            validate_oracle(self.fixture, oracle)

    def test_validator_rejects_selected_candidate_without_episode(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        oracle["segments"][0]["selected_episodes"].pop()

        with self.assertRaisesRegex(ValueError, "selected candidates"):
            validate_oracle(self.fixture, oracle)

    def test_validator_rejects_event_candidate_reference_drift(self) -> None:
        oracle = evaluate_fixture(self.fixture, self.baseline)
        oracle["segments"][0]["event_decisions"][0]["candidate_ids"] = []

        with self.assertRaisesRegex(ValueError, "candidate_ids"):
            validate_oracle(self.fixture, oracle)

    def test_input_pair_fails_closed_on_boundary_or_baseline_drift(self) -> None:
        exclusive = copy.deepcopy(self.fixture)
        exclusive["rule"]["window_boundary"] = "exclusive"
        with self.assertRaisesRegex(ValueError, "only inclusive"):
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


if __name__ == "__main__":
    unittest.main()
