"""Phase 5R: real-Intent package and source task-relevance anti-inflation tests."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5r_telegraph_two_task_consistency as r
from falsum.phase5m_real_source_sensitive_model import ROOT


DEPENDENCY={"intent":"SECURITY_REVIEW_GENERAL",
            "params":{"target":"npm package lodash version 4.17.15"}}
SIMPLE_DIFF=("diff --git a/src/users.js b/src/users.js\n"
             "@@ -1,2 +1,3 @@\n"
             " const db = require('./db');\n"
             "+const userId = req.query.id;\n"
             "+db.query(\"SELECT * FROM users WHERE id='\" + userId + \"'\");")


class TwoTaskTelegraphConsistencyTests(unittest.TestCase):
    def test_exact_observational_freeze_and_original_sha(self):
        p=r.frozen()
        self.assertEqual(r.git_blob_sha((ROOT/r.LOCK_PATH).read_bytes()),r.LOCK_BLOB)
        self.assertEqual([x["key"] for x in p["original_fixtures"]],
                         list(r.ALLOWED_ROLES))
        self.assertTrue(p["restrictions"]["not_new_blind_holdout"])
        self.assertTrue(p["restrictions"]["only_historical_public_captures"])
        self.assertEqual(p["restrictions"]["independent_expert_gold"],0)
        self.assertTrue(p["restrictions"]["not_multiple_independent_miners"])
        self.assertTrue(p["restrictions"]["do_not_republish_bodies"])
        self.assertTrue(p["preobservation_disclosure"].startswith("The two original public"))

    def test_original_long_generic_advisory_feed_is_off_target(self):
        generic=[{"ghsa_id":f"GHSA-aaaa-bbbb-{i:04d}",
                  "description":"Generic unrelated security disclosure"} for i in range(100)]
        v=r.classify_package(DEPENDENCY,{"result":generic,"paid":True,"status":200})
        self.assertEqual(v["decision"],"OFF_TARGET_ADVISORY_FEED")
        self.assertEqual(v["target_specific_advisory_mentions"],0)
        self.assertTrue(v["result_is_generic_advisory_feed"])
        self.assertIsNone(v["semantic_accuracy"])
        self.assertIsNone(v["network_ranking_delta"])
        self.assertFalse(v["paid_http_status_used_as_quality"])

    def test_package_case_sensitivity_and_another_package(self):
        relevant=[{"ghsa_id":f"GHSA-aaaa-bbbb-{i:04d}",
                   "description":"Package lodash has a reported issue"} if i==8
                  else {"ghsa_id":f"GHSA-aaaa-bbbb-{i:04d}",
                        "summary":"Other library advisory"}
                  for i in range(100)]
        v=r.classify_package(DEPENDENCY,{"result":relevant})
        self.assertEqual(v["decision"],"DEPENDENCY_RELEVANCE_PRESENT_NOT_SEMANTIC_GOLD")
        self.assertIsNone(v["semantic_accuracy"])
        another={"intent":r.CANONICAL,"params":{"target":"npm package express version 4.21.2"}}
        v2=r.classify_package(another,{"result":relevant})
        self.assertEqual(v2["decision"],"OFF_TARGET_ADVISORY_FEED")
        self.assertEqual(v2["target_specific_advisory_mentions"],0)
        self.assertFalse(v2["paid_http_status_used_as_quality"])

    def test_package_citation_not_gold_even_if_claim_untrue(self):
        answer={"result":{"package":"lodash","findings":[
                {"severity":"critical","message":"A fabricated vulnerability."}]}}
        verdict=r.classify_package(DEPENDENCY,answer)
        self.assertEqual(verdict["decision"],"DEPENDENCY_RELEVANCE_PRESENT_NOT_SEMANTIC_GOLD")
        self.assertIsNone(verdict["semantic_accuracy"])

    def test_wrong_intent_or_envelope_not_ranking_peer(self):
        req={"intent":"CODE_REVIEW_GENERAL","params":{"target":DEPENDENCY["params"]["target"]}}
        v=r.classify_package(req,{"result":[]})
        self.assertEqual(v["decision"],"NOT_COMPARABLE_DIFFERENT_INTENT")
        req={"intent":"SECURITY_REVIEW_GENERAL","payload":{"code":"npm package lodash version 4.17.15"}}
        self.assertEqual(r.classify_package(req,{"result":[]})["decision"],
                         "NOT_COMPARABLE_DIFFERENT_REQUEST")

    def test_unsupported_target_not_genuine_quality_score(self):
        v=r.classify_package({"intent":r.CANONICAL,"params":{"target":"arbitrary user question"}},
                             {"result":[{"ghsa_id":"GHSA-xxxx-yyyy-zzzz"}]})
        self.assertEqual(v["decision"],"INSUFFICIENT_EVIDENCE")
        self.assertIsNone(v["semantic_accuracy"])

    def test_diff_uses_existing_verified_code_source_route(self):
        bad=[{"ghsa_id":f"GHSA-aaaa-bbbb-{i:04d}"} for i in range(100)]
        v=r.classify_package({"intent":r.CANONICAL,"params":{"target":SIMPLE_DIFF}},
                             {"result":bad})
        self.assertEqual(v["decision"],"OFF_TARGET_ADVISORY_FEED")
        self.assertIsNone(v["semantic_correctness"])
        self.assertIsNone(v["network_rank_delta"])

    def test_source_freeze_byte_tamper_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            path=root/r.LOCK_PATH
            path.parent.mkdir(parents=True)
            path.write_bytes((ROOT/r.LOCK_PATH).read_bytes()+b" ")
            with self.assertRaises(r.TargetRelevanceError):
                r.frozen(root)


if __name__=="__main__":
    unittest.main()
