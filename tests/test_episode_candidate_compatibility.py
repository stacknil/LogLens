import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_episode_candidate import (  # noqa: E402
    ALGORITHM_V1,
    evaluate_fixture,
    main,
)


FIXTURE_ROOTS = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "episode_semantics_v0.7"
    / "continuous_background_two_peaks",
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "episode_semantics_v0.7"
    / "isolated_dense_bursts",
)


def canonical_bytes(value: dict[str, object]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


class CandidateV1CompatibilityTests(unittest.TestCase):
    def test_default_and_explicit_v1_match_committed_bytes(self) -> None:
        for root in FIXTURE_ROOTS:
            with self.subTest(fixture=root.name):
                fixture = json.loads(
                    (root / "fixture.json").read_text(encoding="utf-8")
                )
                baseline = json.loads(
                    (root / "baseline.expected.json").read_text(encoding="utf-8")
                )
                expected = (
                    root / "candidate.window-separated-v1.expected.json"
                ).read_bytes()

                self.assertEqual(
                    canonical_bytes(evaluate_fixture(fixture, baseline)), expected
                )
                self.assertEqual(
                    canonical_bytes(
                        evaluate_fixture(
                            fixture, baseline, algorithm=ALGORITHM_V1
                        )
                    ),
                    expected,
                )

    def test_cli_default_and_explicit_v1_match_committed_bytes(self) -> None:
        root = FIXTURE_ROOTS[0]
        expected = (root / "candidate.window-separated-v1.expected.json").read_bytes()
        for label, algorithm_args in (
            ("default", []),
            ("explicit", ["--algorithm", ALGORITHM_V1]),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "oracle.json"

                status = main(
                    [
                        "--fixture",
                        str(root / "fixture.json"),
                        "--baseline",
                        str(root / "baseline.expected.json"),
                        "--output",
                        str(output),
                        *algorithm_args,
                    ]
                )

                self.assertEqual(status, 0)
                self.assertEqual(output.read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
