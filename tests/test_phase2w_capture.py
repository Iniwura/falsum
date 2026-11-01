"""Test real application evidence capturing without claiming automated semantic proof."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from falsum.phase2w_capture import capture_claims
from falsum.phase2w_proof_gate import ProofError, evaluate_case, validate_catalog
from test_phase2w_proof_gate import inputs


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.catalog,self.sources=inputs()
        self.rule=list(validate_catalog(self.catalog,self.sources).values())[0]
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        (self.root/"app.py").write_text(
            "proxy = 'http://user:secret@proxy.invalid:8080'\n"
            "redirect_to = 'https://example.invalid/'\n"
            "request = {'proxy': proxy, 'redirect': redirect_to}\n",encoding="utf-8")
        ids=[x["id"] for x in self.rule["requirements"]]
        self.claims=[
            {"requirement_id":ids[0],"claim":"present","path":"app.py","line_start":1,"line_end":1},
            {"requirement_id":ids[1],"claim":"present","path":"app.py","line_start":2,"line_end":2},
        ]

    def test_real_application_source_capture_and_conditional_decision(self):
        packet=capture_claims(self.rule,self.root,self.claims)
        self.assertEqual(packet["evidence_origin"],"unreviewed_application_submission")
        self.assertEqual(len(packet["evidence"]),2)
        proof=evaluate_case(self.rule,packet,self.root)
        self.assertEqual(proof["result"],"CONDITIONALLY_APPLICABLE_REVIEW_CANDIDATE")
        self.assertFalse(proof["actual_application_semantics_verified"])
        self.assertFalse(proof["confirmed_security_finding"])
        expected=hashlib.sha256((self.root/"app.py").read_bytes()).hexdigest()
        self.assertTrue(all(r["sha256"]==expected for r in packet["evidence"]))

    def test_changed_real_application_is_detected_after_capture(self):
        packet=capture_claims(self.rule,self.root,self.claims)
        (self.root/"app.py").write_text("proxy = None\n")
        with self.assertRaisesRegex(ProofError,"changed"):
            evaluate_case(self.rule,packet,self.root)

    def test_submitted_absent_claim_changes_only_provisional_status(self):
        claims=copy.deepcopy(self.claims)
        claims[0]["claim"]="absent"
        packet=capture_claims(self.rule,self.root,claims)
        proof=evaluate_case(self.rule,packet,self.root)
        self.assertEqual(proof["result"],"APPLICABILITY_PRECONDITION_CONTRADICTED")
        self.assertFalse(proof["actual_application_semantics_verified"])
        # This intentionally proves user-provided semantic assertions are NOT
        # verified automatically, even when exact file bytes do match.
        self.assertIn("user:secret",packet["evidence"][0]["quote"])

    def test_missing_precondition_stays_unresolved(self):
        packet=capture_claims(self.rule,self.root,self.claims[:1])
        self.assertEqual(evaluate_case(self.rule,packet,self.root)["result"],
                         "INSUFFICIENT_APPLICATION_EVIDENCE")

    def test_invalid_requirement_cannot_be_injected(self):
        claims=copy.deepcopy(self.claims)
        claims[0]["requirement_id"]="unrelated_credential_theft"
        with self.assertRaisesRegex(ProofError,"not in source-pinned"):
            capture_claims(self.rule,self.root,claims)

    def test_cannot_fake_user_approval_or_new_claim_field(self):
        claims=copy.deepcopy(self.claims)
        claims[0]["expert_verified"]=True
        with self.assertRaisesRegex(ProofError,"claim schema changed"):
            capture_claims(self.rule,self.root,claims)

    def test_symlink_local_capture_blocked(self):
        (self.root/"link.py").symlink_to(self.root/"app.py")
        claims=copy.deepcopy(self.claims)
        claims[0]["path"]="link.py"
        with self.assertRaisesRegex(ProofError,"symlink"):
            capture_claims(self.rule,self.root,claims)

    def test_invalid_lines_fail_before_manifest_written(self):
        for start,end in ((0,1),(True,1),(8,9),(1,16)):
            claims=copy.deepcopy(self.claims)
            claims[0]["line_start"]=start
            claims[0]["line_end"]=end
            with self.subTest(start=start,end=end),self.assertRaises(ProofError):
                capture_claims(self.rule,self.root,claims)

    def test_empty_or_unbounded_claims_rejected(self):
        with self.assertRaises(ProofError):
            capture_claims(self.rule,self.root,[])
        with self.assertRaises(ProofError):
            capture_claims(self.rule,self.root,self.claims*15)


if __name__=="__main__":
    unittest.main()
