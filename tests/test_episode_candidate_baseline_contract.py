import copy
import json
import sys
import unittest
from datetime import timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.episode_baseline_contract import (  # noqa: E402
    canonical_oracle_timestamp,
    finding_id,
    validate_fixture_baseline,
)
from scripts.episode_candidate_core import parse_timestamp  # noqa: E402


FIXTURE_ROOT = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "episode_semantics_v0.7"
    / "continuous_background_two_peaks"
)


class EpisodeBaselineContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(
            (FIXTURE_ROOT / "fixture.json").read_text(encoding="utf-8")
        )
        self.baseline = json.loads(
            (FIXTURE_ROOT / "baseline.expected.json").read_text(encoding="utf-8")
        )

    def test_committed_baseline_replays_v06_selection_and_identity(self) -> None:
        context = validate_fixture_baseline(self.fixture, self.baseline)

        self.assertEqual(context.episode_count, 1)
        self.assertEqual(len(context.selections), 1)
        self.assertEqual(
            finding_id(self.fixture["rule"], context.selections[0]),
            "finding:brute_force:584fd14b544a7959",
        )

    def test_equivalent_timezone_offsets_preserve_baseline_identity(self) -> None:
        offset_fixture = copy.deepcopy(self.fixture)
        offset = timezone(timedelta(hours=1))
        for event in offset_fixture["events"]:
            event["timestamp"] = parse_timestamp(event["timestamp"]).astimezone(
                offset
            ).isoformat()

        original = validate_fixture_baseline(self.fixture, self.baseline)
        shifted = validate_fixture_baseline(offset_fixture, self.baseline)

        self.assertEqual(
            [canonical_oracle_timestamp(item.first_seen) for item in shifted.selections],
            [canonical_oracle_timestamp(item.first_seen) for item in original.selections],
        )
        self.assertEqual(
            [finding_id(offset_fixture["rule"], item) for item in shifted.selections],
            [finding_id(self.fixture["rule"], item) for item in original.selections],
        )

    def test_unsupported_rule_contracts_fail_closed(self) -> None:
        mutations = {
            "rule": ("rule_id", "multi_user_probing"),
            "grouping": ("grouping_key", "username"),
            "boundary": ("window_boundary", "exclusive"),
            "signal": ("signal_kind", "sudo_command"),
        }

        for label, (field, value) in mutations.items():
            with self.subTest(label=label):
                fixture = copy.deepcopy(self.fixture)
                baseline = copy.deepcopy(self.baseline)
                fixture["rule"][field] = value
                if field in baseline["rule"]:
                    baseline["rule"][field] = value
                with self.assertRaisesRegex(ValueError, "candidate v1 supports only"):
                    validate_fixture_baseline(fixture, baseline)

    def test_fixture_events_must_match_the_rule_subject(self) -> None:
        fixture = copy.deepcopy(self.fixture)
        fixture["events"][0]["source_ip"] = "203.0.113.99"

        with self.assertRaisesRegex(ValueError, "fixture events"):
            validate_fixture_baseline(fixture, self.baseline)

    def test_semantically_stale_baseline_fails_closed(self) -> None:
        mutations = {
            "algorithm": lambda baseline: baseline["algorithm"].__setitem__(
                "id", "stale.algorithm"
            ),
            "finding identity": lambda baseline: baseline["expected_output"][
                "findings"
            ][0].__setitem__("finding_id", "finding:brute_force:stale"),
            "selected window": lambda baseline: baseline["candidate_windows"][
                0
            ].__setitem__("last_seen", "2026-03-10T09:01:30Z"),
            "segment evidence": lambda baseline: baseline["derived_input"][
                "activity_segments"
            ][0].__setitem__("max_adjacent_gap_seconds", 539),
        }

        for label, mutate in mutations.items():
            with self.subTest(label=label):
                baseline = copy.deepcopy(self.baseline)
                mutate(baseline)
                with self.assertRaisesRegex(ValueError, "baseline"):
                    validate_fixture_baseline(self.fixture, baseline)


if __name__ == "__main__":
    unittest.main()
