"""Phase 3Z synthetic integrity tests. NEVER a real-model or human-label result."""
import copy
import json
import unittest
from unittest.mock import patch

from falsum import phase3z_catalogue_reversals as mod


class Phase3ZNewFamilyTests(unittest.TestCase):
    def setUp(self):
        self.pins = []
        self.sources = {}
        self.release_payloads = {}
        for pin in mod.PINS:
            ghsa, path, _, package, start, fixed, older, newer, count = pin
            affected = [{
                "package": {"ecosystem": "PyPI", "name": package},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": start}, {"fixed": fixed}
                ]}],
            }]
            if count == 2:
                affected.append({
                    "package": {"ecosystem": "PyPI", "name": package},
                    "ranges": [{"type": "ECOSYSTEM", "events": [
                        {"introduced": "1.4.0.dev9"}, {"fixed": "1.4.0rc3"}
                    ]}],
                })
            advisory = json.dumps({
                "id": ghsa, "published": "2026-10-27T12:00:00Z",
                "withdrawn": None, "affected": affected,
            }, sort_keys=True, separators=(",", ":")).encode()
            blob = mod.git_blob_sha1(advisory)
            self.pins.append((ghsa, path, blob, package, start, fixed, older, newer, count))
            self.sources[mod.advisory_url(pin)] = advisory
            for version in (older, newer):
                release = json.dumps({
                    "info": {"name": package, "version": version},
                    "urls": [{
                        "yanked": False, "digests": {"sha256": "d"*64},
                        "upload_time_iso_8601": "2026-10-01T00:00:00.000000Z",
                    }],
                }, sort_keys=True, separators=(",", ":")).encode()
                self.release_payloads[mod.pypi_url(package, version)] = release
        self.sources.update(self.release_payloads)

    def synthetic(self, values=None, pins=None):
        with patch.object(mod, "PINS", tuple(pins or self.pins)):
            return mod.assemble(fetcher=lambda url: (values or self.sources)[url])

    def test_six_verified_catalogue_cases_are_source_disjoint_and_balanced(self):
        report = self.synthetic()
        self.assertEqual(report["distinct_package_projects"], 3)
        self.assertEqual(report["case_count"], 6)
        self.assertEqual(report["catalogue_version_reversal_pairs"], 3)
        self.assertEqual([x["mechanically_source_derived_preference"] for x in report["cases"]],
                         ["A", "B"]*3)
        self.assertEqual(report["source_catalogue_expected_A"], 3)
        self.assertEqual(report["source_catalogue_expected_B"], 3)
        self.assertTrue(report["not_blind_or_private_holdout"])
        self.assertTrue(report["not_independent_expert_reviewed"])
        self.assertEqual(report["independent_expert_labels"], 0)
        self.assertFalse(report["automatic_registration_permitted"])
        self.assertEqual(report["new_network_eligible_rows"], 0)
        self.assertFalse(report["model_scores_measured"])
        self.assertFalse(report["registered_evaluator"])
        self.assertEqual(report["trainable_pairs"], [])
        for c in report["cases"]:
            self.assertEqual(c["candidate_answers"][0]["text"], mod.ANSWER_A)
            self.assertEqual(c["candidate_answers"][1]["text"], mod.ANSWER_B)
            self.assertTrue(c["public_catalogue_question_not_independent_expert_label"])
            self.assertFalse(c["training_authorized"])

    def test_deep_source_identity_and_all_range_count_are_verified(self):
        report = self.synthetic()
        self.assertEqual(len(report["provenance"]), 3)
        self.assertEqual([p["complete_advisory_affected_ranges"]
                          for p in report["provenance"]], [1, 2, 1])
        self.assertTrue(all(len(p["verified_pypi_releases"]) == 2
                            for p in report["provenance"]))
        bad = list(self.pins)
        bad[0] = tuple(list(bad[0])[:2] + ["0"*40] + list(bad[0])[3:])
        with self.assertRaises(mod.Phase3ZError):
            self.synthetic(pins=bad)
        bad_data = dict(self.sources)
        first = mod.advisory_url(self.pins[0])
        bad_data[first] += b" "
        with self.assertRaises(mod.Phase3ZError):
            self.synthetic(values=bad_data)
        with self.assertRaises(mod.Phase3ZError):
            mod.check_advisory(self.pins[1], self.sources[mod.advisory_url(self.pins[0])])

    def test_wrong_version_or_yanked_pypi_release_rejected(self):
        target = mod.pypi_url(self.pins[0][3], self.pins[0][6])
        for mode in ("wrong-version", "yanked", "no-files", "future-release"):
            with self.subTest(mode=mode):
                bad = dict(self.sources)
                release = json.loads(bad[target])
                if mode == "wrong-version":
                    release["info"]["version"] = "100.0"
                elif mode == "yanked":
                    release["urls"][0]["yanked"] = True
                elif mode == "no-files":
                    release["urls"] = []
                else:
                    release["urls"][0]["upload_time_iso_8601"] = "2027-01-01T01:00:00Z"
                bad[target] = json.dumps(release).encode()
                with self.assertRaises(mod.Phase3ZError):
                    self.synthetic(values=bad)

    def test_untrusted_version_or_reused_project_fails_closed(self):
        for bad in ("1.3.8rc3", "1.4.0.dev9", "-1", "1..2", "1.2+extra", "0.01", "x"):
            with self.subTest(bad=bad), self.assertRaises(mod.Phase3ZError):
                mod.numeric_version(bad)
        self.assertEqual(mod.cmp_version("1.3.7", "1.3.8"), -1)
        self.assertEqual(mod.cmp_version("2.48.4", "2.48.4"), 0)
        bad = list(self.pins)
        p = list(bad[0])
        p[3] = "requests"
        bad[0] = tuple(p)
        with self.assertRaises(mod.Phase3ZError):
            self.synthetic(pins=bad)
        bad = list(self.pins)
        bad[1] = bad[0]
        with self.assertRaises(mod.Phase3ZError):
            self.synthetic(pins=bad)

    def test_no_arbitrary_network_targets(self):
        for url in ("http://pypi.org/pypi/docling-core/2.48.3/json",
                    "https://evil.test/steal",
                    "https://pypi.org/pypi/requests/2.31.0/json"):
            with self.assertRaises(mod.Phase3ZError):
                mod.bounded_download(url)

    def test_affected_fixed_labels_not_confused_with_deployment_exploits(self):
        report = self.synthetic()
        for ix in range(0, 6, 2):
            old, patched = report["cases"][ix:ix+2]
            self.assertEqual(old["advisory"], patched["advisory"])
            self.assertEqual(old["source_package"], patched["source_package"])
            self.assertTrue(old["version_in_this_one_advisory_range"])
            self.assertFalse(patched["version_in_this_one_advisory_range"])
            self.assertEqual(old["mechanically_source_derived_preference"], "A")
            self.assertEqual(patched["mechanically_source_derived_preference"], "B")
            self.assertIn("Do not infer application exploitability", old["question"])

    def test_permanent_real_source_receipt_is_provenance_bound_and_not_a_model_result(self):
        from pathlib import Path
        record = json.loads((Path(__file__).resolve().parents[1]
                             / "evidence/phase3z-2026-11-12-pinned-real-advisory-receipt.json").read_text())
        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["verified_at"], "2026-11-12")
        self.assertIn("/actions/runs/43286926731", record["source_run_url"])
        self.assertIn("13975646173", record["source_artifact_url"])
        self.assertEqual(record["source_artifact_report_sha256"],
                         "82347910cb443f2b1cbde565107dbbd280f40e884ca45f2abfd501a8a5d108a8")
        self.assertEqual(record["pinned_advisory_database_commit"], mod.PINNED_DB_COMMIT)
        self.assertEqual(set(record["advisory_source_sha256"]),
                         {pin[0] for pin in mod.PINS})
        self.assertEqual([x["package"] for x in record["source_release_facts"]],
                         [pin[3] for pin in mod.PINS])
        self.assertEqual(record["observed_correct_catalogue_order"], ["A", "B"]*3)
        self.assertEqual(record["external_human_expert_review_count"], 0)
        self.assertEqual(record["new_network_eligible_rows"], 0)
        self.assertFalse(record["actual_model_scoring_run"])
        self.assertFalse(record["blind_holdout"])
        self.assertFalse(record["training_allowed"])
        self.assertFalse(record["registered_evaluator"])


if __name__ == "__main__":
    unittest.main()
