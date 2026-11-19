"""Tamper and claim-boundary tests. Synthetic reports are NOT execution evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from test_phase3h_starlette_runtime import sample as starlette_sample
from test_phase3i_requests_runtime import example as requests_example
from falsum import phase4y_cross_family_replay as replay

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json"
LOCK = ROOT / "data/phase4p-three-project-open-review-lock.json"
STARLETTE_QUEUE = ROOT / "data/real-fix-train-candidates.json"
REQUESTS_QUEUE = ROOT / "data/real-fix-queue.json"


def inputs() -> dict:
    return {
        "source_index": INDEX.read_bytes(),
        "source_lock": LOCK.read_bytes(),
        "starlette_before": starlette_sample("0.26.1"),
        "starlette_after": starlette_sample("0.27.0"),
        "requests_before": requests_example("2.30.0"),
        "requests_after": requests_example("2.31.0"),
        "starlette_queue": STARLETTE_QUEUE,
        "requests_queue": REQUESTS_QUEUE,
    }


class CrossFamilyReplayTests(unittest.TestCase):
    def test_two_distinct_historical_source_families_outside_original_four(self):
        report = replay.check(**inputs())
        self.assertEqual(report["cross_family_replayed_boundaries"], 2)
        self.assertEqual(report["cross_family_distinct_projects"], 2)
        self.assertEqual(report["existing_source_executed_stages"], 4)
        self.assertEqual(report["total_distinct_historical_projects_across_two_evidence_methods"], 5)
        self.assertTrue(report["already_studied_in_phases_3h_and_3i"])
        self.assertEqual(
            {row["repository"] for row in report["out_of_four_cases"]},
            {"Kludex/starlette", "psf/requests"},
        )
        self.assertEqual([row["unchanged_controls"] for row in report["out_of_four_cases"]], [3, 4])

    def test_does_not_relabel_historical_replay_as_fresh_model_benchmark(self):
        result = replay.check(**inputs())
        self.assertEqual(result["genuinely_pre_registered_unseen_projects_tested"], 0)
        self.assertEqual(result["novel_cases_where_checker_correctly_recognizes_source_facts"], 0)
        self.assertFalse(result["source_witness_checker_extended_to_these_cases"])
        self.assertEqual(result["independent_human_appsec_labels"], 0)
        self.assertFalse(result["trained_model_scored_on_new_cases"])
        self.assertFalse(result["trained_model_generalization_proven"])
        self.assertFalse(result["registered_telegraph_evaluator"])
        self.assertFalse(result["official_h2_entry_submitted"])

    def test_swapped_releases_fail_closed(self):
        for before, after in (
            ("starlette_before", "starlette_after"),
            ("requests_before", "requests_after"),
        ):
            with self.subTest(family=before):
                item = inputs()
                item[before], item[after] = item[after], item[before]
                with self.assertRaises(ValueError):
                    replay.check(**item)

    def test_tampered_historical_security_or_control_result_cannot_pass(self):
        changes = (
            ("starlette_before", lambda d: d["results"][3].update(status=404)),
            ("starlette_after", lambda d: d.update(independent_human_labels=1)),
            ("starlette_after", lambda d: d.update(runtime_source_sha256="x" * 64)),
            ("requests_before", lambda d: d["observations"][0].update(
                proxy_authorization_header_after_rebuild=False)),
            ("requests_after", lambda d: d.update(accepted_anjoman_rows=1)),
            ("requests_after", lambda d: d.update(no_socket_or_http_transport=False)),
        )
        for key, mutate in changes:
            with self.subTest(key=key, change=str(mutate)):
                docs = inputs()
                mutate(docs[key])
                with self.assertRaises(ValueError):
                    replay.check(**docs)

    def test_laundered_original_four_run_receipt_rejected(self):
        docs = inputs()
        index = json.loads(docs["source_index"])
        index["receipts"][0]["raw_source_runtime_receipt_sha256"] = "0" * 64
        docs["source_index"] = json.dumps(index).encode()
        with self.assertRaises(ValueError):
            replay.check(**docs)

    def test_unapproved_original_source_lock_rejected(self):
        docs = inputs()
        docs["source_lock"] = b'{"not_the_pinned_four":true}'
        with self.assertRaises(ValueError):
            replay.check(**docs)

    def test_corrupt_historical_source_queue_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            original = json.loads(STARLETTE_QUEUE.read_text())
            row = next(x for x in original["cases"] if x["id"] == replay.STARLETTE_CASE)
            row["source_blob"] = "f" * 40
            path = Path(directory) / "fake-queue.json"
            path.write_text(json.dumps(original))
            docs = inputs()
            docs["starlette_queue"] = path
            with self.assertRaises(ValueError):
                replay.check(**docs)

    def test_duplicate_json_properties_rejected_before_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "forged.json"
            p.write_text('{"status":"PASS","status":"FAIL"}')
            with self.assertRaisesRegex(replay.ReplayError, "invalid JSON"):
                replay.read_json(p)

    def test_oversized_and_symlinked_report_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b"x" * (replay.MAX_REPORT_BYTES + 1))
            with self.assertRaises(replay.ReplayError):
                replay.read_json(path)
            link = Path(directory) / "linked.json"
            link.symlink_to(path)
            with self.assertRaises(replay.ReplayError):
                replay.read_json(link)

    def test_synthetic_reports_do_not_become_real_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {}
            for name, data in (
                ("starlette_before", starlette_sample("0.26.1")),
                ("starlette_after", starlette_sample("0.27.0")),
                ("requests_before", requests_example("2.30.0")),
                ("requests_after", requests_example("2.31.0")),
            ):
                files[name] = root / (name + ".json")
                files[name].write_text(json.dumps(data))
            # This validates structure but is NOT a claim that synthetic test
            # fixtures are authenticated package executions.
            report = replay.check(**inputs())
            self.assertIn("An untrusted JSON report alone cannot prove", report["limitations"])
            for p in files.values():
                item, digest = replay.read_json(p)
                self.assertIsInstance(item, dict)
                self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
