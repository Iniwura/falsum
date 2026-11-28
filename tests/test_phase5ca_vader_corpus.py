from __future__ import annotations

import json
import unittest

from falsum.phase5ca_vader_corpus import (
    MODELS,
    _holdout_bucket,
    _model_response,
    build_report,
    canonical_repository,
    git_blob_sha1,
    load_protocol,
    _read_csv,
    VADER_FIELDS,
)


class Phase5CAVaderCorpusTests(unittest.TestCase):
    def test_frozen_protocol_blob_and_private_overlap_boundary(self):
        protocol = load_protocol()
        self.assertEqual(protocol["dataset"]["revision"], "9bef4b3b1994ce138d8a043b68ab0d8a81d8472d")
        self.assertEqual(protocol["private_material_boundary"]["private_anjoman_source_overlap"], "UNKNOWN")
        self.assertFalse(protocol["private_material_boundary"]["claim_fully_disjoint_from_private_anjoman_material"])

    def test_git_blob_sha1_uses_git_object_header(self):
        self.assertEqual(
            git_blob_sha1(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )

    def test_repository_normalization_ignores_file_path_and_fragment(self):
        self.assertEqual(
            canonical_repository("https://github.com/Saleor/Saleor/blob/main/file.py"),
            "saleor/saleor",
        )
        self.assertEqual(canonical_repository("kunzbhatia/Library-Management-System/blob/main/User.py"),
                         "kunzbhatia/library-management-system")
        self.assertEqual(canonical_repository("Dungyichao/http_server#"), "dungyichao/http_server")

    def test_holdout_assignment_is_repository_stable(self):
        self.assertEqual(_holdout_bucket("saleor/saleor"), _holdout_bucket("saleor/saleor"))
        self.assertIn(_holdout_bucket("saleor/saleor"), range(5))

    def test_empty_answer_is_preserved_as_an_abstention_not_dropped(self):
        row = {
            "o3": "",
            "o3-explanation": "0",
            "o3-remediation": "0",
            "o3-other": "0",
            "o3-rating": "0",
        }
        result = _model_response(row, "o3")
        self.assertFalse(result["answer_present"])
        self.assertEqual(result["total"], 0)
        self.assertFalse(result["strict_json_object"])

    def _protocol(self):
        return {
            "dataset": {"repository": "AfterQuery/vader", "revision": "frozen-test-revision"},
            "expected": {"cases_per_source_file": 1},
            "known_public_falsum_source_inventory": {
                "completeness": "TEST_PARTIAL",
                "repositories": [],
            },
            "selection": {
                "minimum_matched_case_count_for_benchmark_ready": 1,
                "minimum_reserved_holdout_cases": 0,
                "minimum_reserved_holdout_repositories": 0,
            },
        }

    def _rows(self, *, description="A SQL injection in the query builder.", vader_case="1", graded_case="99"):
        vader = {
            "Case": vader_case,
            "ID": "1745335148884",
            "Repository": "https://github.com/Owner/Repo/blob/main/app.py",
            "CWE": "CWE-89",
            "Severity": "High",
            "Submitted At": "2025-04-27T00:00:00Z",
            "Approved At": "2025-04-28T00:00:00Z",
            "Description": description,
        }
        graded = {
            "Case": graded_case,
            "ID": "1745335148884",
            "Repository": "owner/repo#",
            "CWE": "CWE-89",
            "Severity": "4",
            "Description": description,
        }
        for index, model in enumerate(MODELS):
            total = 9 - index
            explanation = min(2, total)
            remediation = min(5, max(0, total - explanation))
            other = total - explanation - remediation
            graded[model] = json.dumps({
                "cwe_id": "CWE-89",
                "explanation": "The query concatenates untrusted input.",
                "patch": "Use parameterized SQL.",
                "test_plan": ["try a quote payload"],
            })
            graded[model + "-explanation"] = str(explanation)
            graded[model + "-remediation"] = str(remediation)
            graded[model + "-other"] = str(other)
            graded[model + "-comment"] = "reviewed"
            graded[model + "-rating"] = str(total)
        return [vader], [graded]

    def test_stable_id_join_not_case_number_join(self):
        vader_rows, graded_rows = self._rows(vader_case="2", graded_case="1")
        report, roster = build_report(vader_rows, graded_rows, self._protocol(), [])
        self.assertEqual(report["alignment"]["matched_ids"], 1)
        self.assertEqual(report["alignment"]["matched_source_score_records"], 1)
        self.assertEqual(report["alignment"]["case_number_mismatch_count"], 1)
        self.assertEqual(report["corpus"]["derived_pairwise_summary"]["all_pairs"], 15)
        self.assertEqual(report["corpus"]["derived_pairwise_summary"]["strong_derived_preferences_margin_ge_2"], 10)
        self.assertEqual(roster["case_count"], report["source_disjointness"]["reserved_holdout_cases"])
        self.assertFalse(report["claim_limits"]["raw_responses_written_to_report"])
        self.assertEqual(report["source_disjointness"]["private_anjoman_source_overlap"], "UNKNOWN")

    def test_description_mismatch_is_excluded_from_matched_inputs(self):
        vader_rows, graded_rows = self._rows(description="Source-side description.")
        graded_rows[0]["Description"] = "Different scored prompt."
        report, _ = build_report(vader_rows, graded_rows, self._protocol(), [])
        self.assertEqual(report["alignment"]["matched_ids"], 1)
        self.assertEqual(report["corpus"]["matched_cases"], 0)
        self.assertEqual(len(report["alignment"]["source_identity_mismatches_excluded"]), 1)
        self.assertIn("source_metadata_identity_mismatches_excluded", report["benchmark_readiness"]["reasons"])
        self.assertIn("source_metadata_identity_mismatches_excluded", report["benchmark_readiness"]["warnings"])
        self.assertFalse(report["benchmark_readiness"]["ready_for_next_candidate_stage"])


    def test_csv_short_record_is_excluded_and_counted(self):
        import csv
        import io

        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(VADER_FIELDS)
        writer.writerow([
            "1", "1745335148884", "https://github.com/owner/repo",
            "CWE-89", "High", "2025-04-27T00:00:00Z", "2025-04-28T00:00:00Z",
        ])
        rows, diagnostics = _read_csv(stream.getvalue().encode("utf-8"), VADER_FIELDS, "vader.csv")
        self.assertEqual(rows, [])
        self.assertEqual(diagnostics["physical_records"], 1)
        self.assertEqual(diagnostics["valid_records"], 0)
        self.assertEqual(diagnostics["malformed_records"], 1)

    def test_report_propagates_parse_diagnostics_and_blocks_malformed_inputs(self):
        vader_rows, graded_rows = self._rows()
        diagnostics = {
            "vader_csv": {"physical_records": 2, "valid_records": 1, "malformed_records": 1},
            "graded_csv": {"physical_records": 1, "valid_records": 1, "malformed_records": 0},
        }
        report, _ = build_report(vader_rows, graded_rows, self._protocol(), [], diagnostics)
        self.assertEqual(report["source_row_counts"]["vader_csv_malformed_records"], 1)
        self.assertEqual(report["source_row_counts"]["vader_csv_physical_records"], 2)
        self.assertEqual(report["alignment"]["csv_parse_diagnostics"], diagnostics)
        self.assertIn("malformed_csv_records_excluded", report["benchmark_readiness"]["reasons"])
        self.assertTrue(any("malformed records excluded" in item for item in report["benchmark_readiness"]["warnings"]))

    def test_complete_six_model_case_requires_six_nonempty_answers(self):
        vader_rows, graded_rows = self._rows()
        graded_rows[0]["o3"] = ""
        for field in ("o3-explanation", "o3-remediation", "o3-other", "o3-rating"):
            graded_rows[0][field] = "0"
        report, _ = build_report(vader_rows, graded_rows, self._protocol(), [])
        self.assertEqual(report["corpus"]["complete_six_model_cases"], 0)
        self.assertEqual(report["corpus"]["nonempty_model_responses"], 5)
        self.assertEqual(report["corpus"]["published_human_scored_responses"], 6)

    def test_description_line_endings_normalize_before_identity_comparison(self):
        vader_rows, graded_rows = self._rows()
        vader_rows[0]["Description"] = "first line\r\nsecond line  \r\n"
        graded_rows[0]["Description"] = "first line\nsecond line\n"
        report, _ = build_report(vader_rows, graded_rows, self._protocol(), [])
        self.assertEqual(report["corpus"]["matched_cases"], 1)
        self.assertEqual(report["alignment"]["excluded_records"], [])



    def test_unparseable_cwe_is_reported_and_excluded_without_aborting(self):
        vader_rows, graded_rows = self._rows()
        vader_rows[0]["CWE"] = "not classified"
        report, _ = build_report(vader_rows, graded_rows, self._protocol(), [])
        self.assertEqual(report["corpus"]["matched_cases"], 0)
        self.assertEqual(len(report["alignment"]["invalid_source_metadata_excluded"]), 1)
        self.assertIn("invalid_source_metadata_excluded", report["benchmark_readiness"]["reasons"])
        self.assertIn("invalid_source_metadata_records_excluded", report["benchmark_readiness"]["warnings"])



if __name__ == "__main__":
    unittest.main()
