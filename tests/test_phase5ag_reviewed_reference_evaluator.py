"""Phase 5AG preregistered new-package evidence and adversarial source tests.

These are constructed cases with exact Git-reviewed source bytes, not new
independent human expert labels or paid outside Miner responses.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import shutil
import tempfile
import unittest
import json
import io
from contextlib import redirect_stdout

from falsum import phase5ag_reviewed_reference_evaluator as e
from falsum.phase4l_external_receipt_evidence import git_blob_sha
from falsum.phase5m_real_source_sensitive_model import ROOT


class MultiEcosystemReviewedSourceContract(unittest.TestCase):
    def test_preimplementation_frozen_roster_and_source_hashes(self):
        protocol = e.frozen_protocol()
        self.assertEqual(git_blob_sha((ROOT / e.PREREG).read_bytes()), e.PREREG_BLOB)
        self.assertEqual(protocol["source_count"], 3)
        index, sources = e.reviewed_sources()
        self.assertEqual(set(sources), set(e.EXPECTED_IDS))
        self.assertIn("CVE-2023-45857", index)
        self.assertIn("CVE-2024-26141", index)
        self.assertIn("CVE-2026-34763", index)

    def test_thirteen_predeclared_cases_without_rewriting_expected_labels(self):
        fixed = e.frozen_protocol()["constructed_cases"]
        self.assertEqual(len(fixed), 13)
        for case in fixed:
            with self.subTest(case=case["name"]):
                result = e.evaluate(case["target"], case["references"])
                self.assertEqual([d["decision"] for d in result["reference_decisions"]],
                                 case["expected_statuses"])
                self.assertFalse(result["coverage_is_complete"])
                self.assertFalse(result["security_clearance_granted"])
                self.assertEqual(result["independent_expert_appsec_gold"], 0)
                self.assertFalse(result["new_actual_miner_result_evaluated"])

    def test_pinned_modified_time_source_url_and_alias_witness(self):
        result = e.evaluate(
            {"ecosystem": "npm", "package": "axios", "version": "1.5.0"},
            ["CVE-2023-45857"]
        )
        row = result["reference_decisions"][0]
        self.assertEqual(row["decision"], e.APPLICABLE)
        self.assertEqual(row["canonical_ghsa_id"], e.EXPECTED_IDS[0])
        self.assertTrue(row["source_url"].startswith(
            "https://github.com/github/advisory-database/blob/" + e.UPSTREAM_COMMIT + "/"))
        self.assertEqual(row["original_git_blob_sha1"],
                         "ed4df0a27ba60625f1c70cc2baa6173516a16aa2")
        self.assertFalse(row["source_is_current_feed"])

    def test_untrusted_provenance_fields_cannot_create_a_source(self):
        with self.assertRaises(e.SourceEvidenceError):
            e.evaluate({"ecosystem": "npm", "package": "axios", "version": "1.5.0"},
                       {"original_source_verified_by_git_blob": True,
                        "references": ["GHSA-zzzz-zzzz-zzzz"]})
        injected = e.evaluate({"ecosystem": "npm", "package": "axios",
                               "version": "1.5.0", "authentic": True},
                              [e.EXPECTED_IDS[0]])
        self.assertEqual(injected["reference_decisions"][0]["decision"], e.INSUFFICIENT)
        self.assertFalse(injected["security_clearance_granted"])

    def test_malformed_unknown_duplicate_cannot_be_promoted(self):
        d = e.evaluate({"ecosystem": "RubyGems", "package": "rack", "version": "3.2.5"},
                       [e.EXPECTED_IDS[2], "CVE-2026-34763",
                        "GHSA-unknown-unknown-unknown", {}, None])
        self.assertEqual([x["decision"] for x in d["reference_decisions"]],
                         [e.APPLICABLE, e.INSUFFICIENT, e.UNKNOWN,
                          e.INSUFFICIENT, e.INSUFFICIENT])

    def test_version_range_fail_closed(self):
        for target in ("3.0.0.beta1", "3.0.5", "version-3", "3.1.*"):
            with self.subTest(version=target):
                r = e.evaluate({"ecosystem": "RubyGems", "package": "rack",
                                "version": target}, [e.EXPECTED_IDS[2]])
                self.assertEqual(r["reference_decisions"][0]["decision"], e.INSUFFICIENT)

    def test_interval_boundaries_and_number_comparison(self):
        self.assertEqual(e.range_status([{"introduced": "1.0.0"},
                                         {"last_affected": "1.5.0"}],
                                        e.numbers("1.5.0")), e.APPLICABLE)
        self.assertEqual(e.range_status([{"introduced": "1.0.0"},
                                         {"fixed": "1.5.0"}],
                                        e.numbers("1.5.0")), e.INAPPLICABLE)
        self.assertEqual(e.range_status([{"introduced": "1.0.0.beta1"},
                                         {"fixed": "1.5.0"}],
                                        e.numbers("1.3.0")), e.INSUFFICIENT)
        self.assertEqual(e.range_status([{"introduced": "3.2.0"},
                                         {"limit": "3.3.0"}],
                                        e.numbers("3.2.1")), e.INSUFFICIENT)
        # An early matching interval cannot hide a subsequent unparseable event.
        self.assertEqual(e.range_status([{"introduced": "1.0.0"},
                                         {"fixed": "2.0.0"},
                                         {"introduced": "2.0.0.beta1"}],
                                        e.numbers("1.5.0")), e.INSUFFICIENT)
        # Two valid disjoint intervals remain a supported source representation.
        self.assertEqual(e.range_status([{"introduced": "1.0.0"},
                                         {"fixed": "2.0.0"},
                                         {"introduced": "3.0.0"},
                                         {"fixed": "4.0.0"}],
                                        e.numbers("1.5.0")), e.APPLICABLE)

    def test_rejects_out_of_order_overlapping_and_inclusive_interval_reentry(self):
        # New adversarial parser tests, NOT replacements for the 13 frozen
        # preregistration cases or independent AppSec reference labels.
        malformed = [
            # Descending intervals: a later interval starts before an earlier one.
            ([{"introduced": "2.0.0"}, {"fixed": "3.0.0"},
              {"introduced": "1.0.0"}, {"fixed": "1.5.0"}], "2.5.0"),
            # Overlapping intervals cannot become verified merely because
            # the first interval already matched the queried version.
            ([{"introduced": "1.0.0"}, {"fixed": "2.0.0"},
              {"introduced": "1.9.0"}, {"fixed": "3.0.0"}], "1.5.0"),
            # last_affected is inclusive, so reopening on the same release
            # double-counts a boundary in a contradictory event stream.
            ([{"introduced": "1.0.0"}, {"last_affected": "2.0.0"},
              {"introduced": "2.0.0"}, {"fixed": "3.0.0"}], "2.0.0"),
            # Range ordering cannot be repaired by a subsequent good interval.
            ([{"introduced": "1.0.0"}, {"fixed": "2.0.0"},
              {"introduced": "1.0.0"}, {"last_affected": "4.0.0"}], "3.0.0"),
        ]
        for events, target in malformed:
            with self.subTest(events=events, target=target):
                self.assertEqual(e.range_status(events, e.numbers(target)),
                                 e.INSUFFICIENT)
        # Reopening at an exclusive fixed boundary is a legal adjacent range.
        adjacent = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"},
                    {"introduced": "2.0.0"}, {"fixed": "3.0.0"}]
        for version, expected in (("1.5.0", e.APPLICABLE),
                                  ("2.0.0", e.APPLICABLE),
                                  ("2.5.0", e.APPLICABLE),
                                  ("3.0.0", e.INAPPLICABLE)):
            with self.subTest(adjacent=version):
                self.assertEqual(e.range_status(adjacent, e.numbers(version)),
                                 expected)

    def test_public_cli_subcommand_matches_standalone_review(self):
        from falsum.cli import main as falsum_main
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "references.json"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = falsum_main([
                    "review-verified-references", "--ecosystem", "npm",
                    "--package", "axios", "--version", "1.5.0",
                    "--reference", e.EXPECTED_IDS[0], "--out", str(out),
                ])
            self.assertEqual(code, 0, buffer.getvalue())
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result["reference_decisions"][0]["decision"], e.APPLICABLE)
            self.assertFalse(result["security_clearance_granted"])
            # Create-only outputs must never silently overwrite prior evidence.
            with redirect_stdout(io.StringIO()):
                self.assertEqual(falsum_main([
                    "review-verified-references", "--ecosystem", "npm",
                    "--package", "axios", "--version", "1.5.0",
                    "--reference", e.EXPECTED_IDS[0], "--out", str(out),
                ]), 1)

    def test_tamper_original_byte_or_preregistration_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            relative = [e.PREREG] + [
                "evidence/phase5ag-reviewed-advisories/" + ghsa + ".json"
                for ghsa in e.EXPECTED_IDS]
            for file in relative:
                dst = root / file
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / file, dst)
            original = root / relative[1]
            original.write_bytes(original.read_bytes() + b" ")
            with self.assertRaisesRegex(e.SourceEvidenceError, "byte identity"):
                e.reviewed_sources(root)
            shutil.copyfile(ROOT / relative[1], original)
            lock = root / e.PREREG
            lock.write_bytes(lock.read_bytes() + b" ")
            with self.assertRaisesRegex(e.SourceEvidenceError, "preregistration"):
                e.reviewed_sources(root)


if __name__ == "__main__":
    unittest.main()
