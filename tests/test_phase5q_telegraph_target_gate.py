"""Phase 5Q: source-blind/echo attacks and fair Intent comparison guards."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5q_telegraph_target_gate as g
from falsum.phase4l_external_receipt_evidence import SPECS
from falsum.phase5m_real_source_sensitive_model import ROOT


DIFF=(
    "diff --git a/src/users.js b/src/users.js\n"
    "@@ -1,3 +1,6 @@\n"
    " const db = require('./db');\n"
    "+app.get('/user', async (req, res) => {\n"
    "+  const rows = await db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\");\n"
    "+  res.json(rows);\n"
    "+});\n"
    "+app.post('/calc', (req, res) => res.send(String(eval(req.body.expr))));"
)
REQ={"intent":"SECURITY_REVIEW_GENERAL","params":{"target":DIFF}}
CODE_LINE="  const rows = await db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\");"


class TelegraphCanonicalTriageTests(unittest.TestCase):
    def test_preimplementation_contract_byte_identity_and_provenance(self):
        p=g.protocol()
        self.assertEqual(
            g.git_blob_sha((ROOT/g.PROTOCOL_PATH).read_bytes()),
            g.PROTOCOL_BLOB_SHA1)
        self.assertEqual(
            tuple(p["original_external_capture_roles"]),g.ROLE_ORDER)
        self.assertEqual(
            p["original_external_capture_roles"]["canonical_same_intent"]["git_blob_sha1"],
            SPECS["routed_security"]["blob"])
        self.assertTrue(p["no_known_independent_expert_gold"])
        self.assertTrue(p["no_network_ranking_modification"])
        self.assertTrue(p["no_new_same_intent_comparable_positive_miner"])
        self.assertFalse(p["original_attested_payment_cryptographically_verified"])
        self.assertTrue(p["excluded_same_owner_miner"])

    def test_new_line_numbers_and_exact_anchor(self):
        parsed=g.parse_diff(DIFF)
        self.assertEqual(set(parsed),{"src/users.js"})
        self.assertEqual(parsed["src/users.js"][3],CODE_LINE)
        self.assertIn("eval(req.body.expr)",parsed["src/users.js"][6])
        self.assertEqual(len(parsed["src/users.js"]),5)

    def test_malformed_diff_fails_closed(self):
        bad=[
            "", "some unrelated input",
            "diff --git a/x.py b/y.py\n@@ -1 +1 @@\n+eval(x)",
            "diff --git a/../private.key b/../private.key\n@@ -1 +1 @@\n+eval(x)",
            "diff --git a/src/f b/src/f\n+eval(x)",
            "diff --git a/src/f b/src/f\n@@ -1 +1 @@\n+eval(x)\n@@ -1 +1 @@\n+eval(y)",
            "diff --git a/a b/a\n@@ -1 +1 @@\n+foo\rbar",
            "diff --git a/a b/a\n@@ -1 +1 @@\n+foo\x00",
            "diff --git a/a b/a\n@@ -1 +1 @@\n+foo"*20000,
        ]
        for sample in bad:
            with self.subTest(sample=sample[:45]):
                with self.assertRaises(g.TargetRelevanceError):
                    g.parse_diff(sample)

    def test_realistic_unrelated_ghsa_listing_rejected_regardless_of_paid(self):
        feed=[{"ghsa_id":f"GHSA-aaaa-bbbb-{i:04d}","summary":"src/users.js sql injection suspicious!"}
              for i in range(100)]
        result=g.classify(REQ,{"result":feed,"paid":True,"status":200})
        self.assertEqual(result["decision"],"OFF_TARGET_ADVISORY_FEED")
        self.assertFalse(result["paid_or_http_status_used_as_quality_proxy"])
        self.assertIsNone(result["semantic_correctness"])
        self.assertIsNone(result["network_rank_delta"])
        self.assertEqual(result["source_citation_count"],0)

    def test_noncomparable_direct_and_other_intent_cannot_be_ranked(self):
        d=g.classify(
            {"intent":"SECURITY_REVIEW","params":{"target":DIFF}},
            {"result":{"findings":[]}})
        self.assertEqual(d["decision"],"NOT_COMPARABLE_DIFFERENT_INTENT")
        d=g.classify(
            {"intent":"CODE_REVIEW_GENERAL","params":{"code":DIFF}},
            {"result":{"findings":[]}})
        self.assertEqual(d["decision"],"NOT_COMPARABLE_DIFFERENT_INTENT")
        d=g.classify(
            {"intent":"SECURITY_REVIEW_GENERAL","payload":{"input":{"code":DIFF}}},
            {"result":{"findings":[]}})
        self.assertEqual(d["decision"],"NOT_COMPARABLE_DIFFERENT_REQUEST")

    def test_diff_echo_and_glossy_security_claim_without_evidence_fail(self):
        variants=[
            {"result":{"summary":DIFF,"verdict":"Critical"}},
            {"result":{"findings":[{"message":"SQL injection occurs in source; check carefully"}]}},
            {"result":{"findings":[{"file_path":"src/users.js","line":3,
                                    "message":"SQL injection risk because unsafe SQL concatenation"}]}},
            {"result":{"findings":[{"file_path":"src/users.js","line":333,
                                    "source_line":CODE_LINE,
                                    "message":"SQL injection risk because unsafe SQL concatenation"}]}},
            {"result":{"findings":[{"file_path":"fake.py","line":3,
                                    "source_line":CODE_LINE,
                                    "message":"SQL injection risk because unsafe SQL concatenation"}]}},
            {"result":{"findings":[{"file_path":"src/users.js","line":3,
                                    "source_line":"not the original added line",
                                    "message":"SQL injection risk because unsafe SQL concatenation"}]}},
            {"result":{"findings":["SQL Injection: "+CODE_LINE]}},
            {"result":{"findings":[]}},
        ]
        for body in variants:
            with self.subTest(body=str(body)[:70]):
                r=g.classify(REQ,body)
                self.assertEqual(r["decision"],"INSUFFICIENT_EVIDENCE")
                self.assertIsNone(r["semantic_correctness"])

    def test_structured_line_reference_only_traceability_not_accuracy(self):
        candidate={"result":{"findings":[{
            "file_path":"src/users.js",
            "line":3,"source_line":CODE_LINE,
            "severity":"critical",
            "message":"A query concatenates user input, so injection deserves investigation."
        }]}}
        r=g.classify(REQ,candidate)
        self.assertEqual(r["decision"],"REVIEW_STRUCTURE_PRESENT_NOT_SEMANTIC_GOLD")
        self.assertEqual(r["source_citation_count"],1)
        self.assertIsNone(r["semantic_correctness"])
        self.assertIsNone(r["network_rank_delta"])
        self.assertFalse(r["paid_or_http_status_used_as_quality_proxy"])

    def test_source_spec_alignment_and_no_excluded_miner(self):
        src=g.protocol()["original_external_capture_roles"]
        for role,name in g.ORIGINAL_ROLE.items():
            self.assertNotEqual(SPECS[name]["miner_id"],"731001")
            self.assertEqual(src[role]["git_blob_sha1"],SPECS[name]["blob"])

    def test_tampered_protocol_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)
            x=base/g.PROTOCOL_PATH
            x.parent.mkdir(parents=True)
            x.write_bytes((ROOT/g.PROTOCOL_PATH).read_bytes()+b"\n")
            with self.assertRaises(g.TargetRelevanceError):
                g.protocol(base)

    def test_local_response_never_pretends_paid_or_network_scoring(self):
        candidate={"result":{"findings":[{"file_path":"src/users.js","line":3,
                      "source_line":CODE_LINE,
                      "message":"A query concatenates user input; possible injection"}]}}
        self.assertIsNone(g.classify(REQ,candidate)["semantic_correctness"])
        self.assertIsNone(g.classify(REQ,candidate)["network_rank_delta"])

if __name__=="__main__":
    unittest.main()
