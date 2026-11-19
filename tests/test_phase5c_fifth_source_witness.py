"""Fail-closed fifth source witness; real archived Flask Actions proof, not expert labels."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5c_fifth_source_witness as ext
from falsum import source_review_witness_gate as old

ROOT = Path(__file__).resolve().parents[1]
INDEX_FILE = ROOT/"evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json"
ORIGINAL_LOCK_FILE = ROOT/"data/phase4p-three-project-open-review-lock.json"
FLASK_LOCK_FILE = ROOT/"data/phase4z-flask-new-source-lock.json"
ARCHIVE_FILE = ROOT/"evidence/phase5c-original-phase4z-github-artifact.zip.b64"
INDEX = INDEX_FILE.read_bytes()
ORIGINAL_LOCK = ORIGINAL_LOCK_FILE.read_bytes()
FLASK_LOCK = FLASK_LOCK_FILE.read_bytes()
ARCHIVE = ARCHIVE_FILE.read_bytes()


class OriginalHistoricalFifthSourceWitnessTests(unittest.TestCase):
    def test_real_downloaded_original_github_artifact_is_sha_bound(self):
        lock, report = ext.load_artifact(ARCHIVE, FLASK_LOCK)
        self.assertEqual(lock["case_id"],"flask-session-cookie-vary")
        self.assertEqual(report["test_exit_statuses"], {
            "parent-original":0,"parent-regression":1,"fixed-regression":0,
        })
        self.assertTrue(report["real_upstream_pytest_processes_run"])
        self.assertEqual(report["independent_human_security_gold"],0)
        self.assertEqual(report["raw_test_log_sha256"]["parent-regression"],
                         "33e7b416ca10b6097783479997b31bca1ee585f2f33cbcd9251b719b1d07096a")

    def test_archive_exact_zip_is_recoverable_and_original_report_hash_matches(self):
        zip_raw=base64.b64decode(ARCHIVE.strip(),validate=True)
        self.assertEqual(ext.sha(zip_raw),ext.ARCHIVE_SHA256)
        self.assertEqual(len(zip_raw),1580)
        self.assertEqual(ext.ARTIFACT_ID,14529512891)
        self.assertEqual(ext.RUN_ID,44524997174)

    def test_original_four_cases_are_kept_byte_for_byte_and_flask_adds_one(self):
        before=old.validated_index(INDEX,ORIGINAL_LOCK)
        after=ext.source_index(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE)
        self.assertEqual(len(after),5)
        self.assertEqual(len({x["repository"] for x in after.values()}),4)
        for key,witness in before.items():
            self.assertEqual(after[key],witness)
        flask=after["flask-session-cookie-vary"]
        self.assertEqual(flask["repository"],"pallets/flask")
        self.assertEqual(flask["fixed_git_commit"],
                         "8705dd39c4fa563ea0fe0bf84c85da8fcc98b88d")
        self.assertEqual(flask["raw_source_runtime_receipt_sha256"],ext.REPORT_SHA256)

    def test_real_flask_parent_fail_fix_pass_claims_and_unsupported_scope(self):
        index=ext.source_index(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE)
        w=index["flask-session-cookie-vary"]
        for revision,successful in (("parent",False),("fixed",True)):
            for claim,expected in (
                ("UPSTREAM_REGRESSION_PASSES","SUPPORTED" if successful else "CONTRADICTED"),
                ("UPSTREAM_REGRESSION_FAILS","CONTRADICTED" if successful else "SUPPORTED"),
                ("CONFIRMED_PRODUCTION_EXPLOIT","ABSTAIN"),
                ("GUARANTEED_UNIVERSAL_APPLICATION_SAFETY","ABSTAIN"),
            ):
                with self.subTest(revision=revision,claim=claim):
                    c=old.canonical_claim(w,revision,claim)
                    v=old.evaluate(index,c)
                    self.assertEqual(v["verdict"],expected)
                    self.assertFalse(v["trained_model_accuracy_measurement"])

    def test_40_source_derived_controls_not_a_model_generalization_benchmark(self):
        report=ext.run(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE)
        self.assertEqual(report["source_case_count"],5)
        self.assertEqual(report["distinct_upstream_projects"],4)
        self.assertEqual(report["claims_evaluated"],40)
        self.assertEqual((report["supported"],report["contradicted"],report["abstained"]),
                         (10,10,20))
        self.assertEqual(report["internally_constructed_controls"],40)
        self.assertEqual(report["internally_constructed_controls_matching"],40)
        self.assertEqual(report["unverified_caller_expectations_seen"],0)
        self.assertEqual(report["expected_answer_origin"],"INTERNAL_SOURCE_DERIVED_CONTROLS")
        self.assertFalse(report["learned_model_generalization_scored"])
        self.assertFalse(report["truly_blind_new_case_evaluation"])
        self.assertFalse(report["freeform_review_scoring_supported"])
        self.assertEqual(report["independent_human_expert_gold_labels"],0)
        self.assertFalse(report["official_h2_submission_confirmed"])

    def test_caller_can_ask_new_flask_case_without_gold_label_promotion(self):
        index=ext.source_index(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE)
        witness=index["flask-session-cookie-vary"]
        clean=old.canonical_claim(witness,"fixed","UPSTREAM_REGRESSION_PASSES")
        report=ext.run(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE,examples=[
            {"test_id":"valid","claim":clean,"expected":"SUPPORTED"},
            {"test_id":"caller-incorrect-label","claim":clean,"expected":"CONTRADICTED"},
        ])
        self.assertEqual(report["supported"],2)
        self.assertEqual(report["internally_constructed_controls"],0)
        self.assertEqual(report["internally_constructed_controls_matching"],0)
        self.assertEqual(report["unverified_caller_expectations_seen"],2)
        self.assertEqual(report["expected_answer_origin"],"UNVERIFIED_CALLER_EXPECTATIONS")
        self.assertTrue(report["cases"][0]["matches_unverified_caller_expectation"])
        self.assertFalse(report["cases"][1]["matches_unverified_caller_expectation"])
        self.assertEqual(report["independent_human_expert_gold_labels"],0)
        self.assertNotIn("constructed_source_expectation",report["cases"][0])

    def test_wrong_flask_receipt_or_zip_truncation_or_extra_bytes_rejected(self):
        for altered in (
            b"not-an-artifact",
            ARCHIVE.replace(b"UEs",b"XXs",1),
            ARCHIVE + b"extra",
            ARCHIVE[:-48],
            base64.b64encode(b"fake-zip"),
            b"",
        ):
            with self.subTest(size=len(altered)),self.assertRaises(ValueError):
                ext.source_index(INDEX,ORIGINAL_LOCK,FLASK_LOCK,altered)

    def test_forged_source_lock_or_legacy_witness_index_refused(self):
        cases=(
            (INDEX,b'{"false":true}',FLASK_LOCK,ARCHIVE),
            (b'{"invented":true}',ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE),
            (INDEX,ORIGINAL_LOCK,b'{"fake":"flask"}',ARCHIVE),
        )
        for item in cases:
            with self.subTest(which=item[0][:20]),self.assertRaises(ValueError):
                ext.source_index(*item)

    def test_new_case_tampered_test_blob_receipt_and_unknown_revision_abstain(self):
        index=ext.source_index(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE)
        w=index["flask-session-cookie-vary"]
        for revision in ("parent","fixed"):
            clean=old.canonical_claim(w,revision,"UPSTREAM_REGRESSION_PASSES")
            for kind in ("source_blob_sha1","new_security_regression_test_blob_sha1",
                         "actual_execution_receipt_sha256"):
                changed=json.loads(json.dumps(clean))
                changed["evidence"][kind] = "0"*(40 if kind.endswith("sha1") else 64)
                with self.subTest(revision=revision,kind=kind):
                    self.assertEqual(old.evaluate(index,changed)["verdict"],"ABSTAIN")
        wrong=old.canonical_claim(w,"fixed","UPSTREAM_REGRESSION_PASSES")
        wrong["upstream_commit"]="0"*40
        self.assertEqual(old.evaluate(index,wrong)["reason"],"UNSUPPORTED_GIT_REVISION")

    def test_forged_pseudo_expert_score_not_permitted_in_caller_requests(self):
        index=ext.source_index(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE)
        claim=old.canonical_claim(index["flask-session-cookie-vary"],"fixed","UPSTREAM_REGRESSION_PASSES")
        with self.assertRaises(old.SourceWitnessError):
            ext.run(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE,examples=[
                {"test_id":"forgery","claim":dict(claim,certified_expert=True)}
            ])

    def test_duplicate_ids_and_extra_fields_rejected(self):
        index=ext.source_index(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE)
        claim=old.canonical_claim(index["flask-session-cookie-vary"],"fixed","UPSTREAM_REGRESSION_PASSES")
        with self.assertRaises(ext.ExtensionError):
            ext.run(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE,examples=[
                {"test_id":"dup","claim":claim},{"test_id":"dup","claim":claim}
            ])
        with self.assertRaises(ext.ExtensionError):
            ext.run(INDEX,ORIGINAL_LOCK,FLASK_LOCK,ARCHIVE,examples=[
                {"test_id":"invalid","claim":claim,"external_gold":True}
            ])

    def test_cli_exact_github_archive_and_one_time_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"report.json"
            cmd=[
                "--index",str(INDEX_FILE),
                "--source-lock",str(ORIGINAL_LOCK_FILE),
                "--flask-lock",str(FLASK_LOCK_FILE),
                "--flask-proof-b64",str(ARCHIVE_FILE),
                "--out",str(out),
            ]
            self.assertEqual(ext.main(cmd),0)
            report=json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["internally_constructed_controls_matching"],40)
            self.assertEqual(report["source_case_count"],5)
            with self.assertRaises(SystemExit):
                ext.main(cmd)
            self.assertEqual(ext.main(cmd[:-1]+[str(Path(tmp)/"second.json")]),0)
            with self.assertRaises(SystemExit):
                ext.main(cmd[:-1]+[str(FLASK_LOCK_FILE)])

if __name__ == "__main__":
    unittest.main()
