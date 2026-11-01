"""Reviewer attribution claims never become verified expert/security labels."""
import copy
import hashlib
import unittest

from falsum.phase2w_proof_gate import ProofError,_canonical
from falsum.phase3e_review_packets import build
from falsum.phase3e_review_intake import receive,STATUS
from test_phase3e_review_packets import fixtures


def packet():
    return build(*fixtures())


def input_doc(bundle):
    return {
        "schema_version":1,"status":"UNVERIFIED_PUBLIC_REVIEW_SUBMISSIONS",
        "packet_bundle_sha256":hashlib.sha256(_canonical(bundle)).hexdigest(),
        "reviews":[],
    }


def claim(bundle,packet_number=0):
    p=bundle["packets"][packet_number]
    return {
        "packet_id":p["packet_id"],
        "source_git_blob_sha1":p["source"]["git_blob_sha1"],
        "reviewer_github_login":"independent-security-reviewer",
        "review_comment_url":"https://github.com/Iniwura/falsum/issues/137#issuecomment-12345",
        "candidate_preference":"A",
        "explanation":"I inspected the pinned source and dependency declarations, but a production version and route reachability have not been proven independently.",
        "version_evidence_status":"DECLARED_ONLY",
        "runtime_evidence_status":"SOURCE_SYNTAX_ONLY",
        "independent_reviewer_self_attested":True,
    }


class HumanReviewQuarantineTests(unittest.TestCase):
    def test_empty_real_pipeline_does_not_invent_any_reviewers(self):
        b=packet()
        out=receive(b,input_doc(b))
        self.assertEqual(out["status"],STATUS)
        self.assertEqual(out["source_review_packets"],5)
        self.assertEqual(out["self_reported_review_records"],0)
        self.assertEqual(out["verified_independent_human_labels"],0)
        self.assertEqual(out["accepted_training_pairs"],0)
        self.assertFalse(out["network_eligible"])
        self.assertFalse(out["evaluator_registered"])

    def test_self_reported_reviewer_never_enters_training(self):
        b=packet()
        d=input_doc(b);d["reviews"]=[claim(b)]
        out=receive(b,d)
        self.assertEqual(out["self_reported_review_records"],1)
        self.assertEqual(out["verified_independent_human_labels"],0)
        self.assertEqual(out["accepted_training_pairs"],0)
        self.assertTrue(out["need_external_github_attribution_check"])
        self.assertFalse(out["review_claims"][0]["github_comment_author_verified"])
        self.assertFalse(out["review_claims"][0]["underlying_security_facts_verified"])
        self.assertFalse(out["review_claims"][0]["training_eligible"])
        self.assertFalse(out["network_eligible"])

    def test_forged_source_blob_or_bundle_digest_rejected(self):
        b=packet()
        for kind in ("bundle","source"):
            with self.subTest(kind=kind):
                d=input_doc(b);d["reviews"]=[claim(b)]
                if kind=="bundle":
                    d["packet_bundle_sha256"]="0"*64
                else:
                    d["reviews"][0]["source_git_blob_sha1"]="1"*40
                with self.assertRaises(ProofError):
                    receive(b,d)

    def test_duplicate_claims_by_same_reviewer_rejected(self):
        b=packet(); d=input_doc(b);d["reviews"]=[claim(b),claim(b)]
        with self.assertRaises(ProofError):
            receive(b,d)

    def test_owner_cannot_self_attest_independent_review(self):
        b=packet(); d=input_doc(b);d["reviews"]=[claim(b)]
        d["reviews"][0]["reviewer_github_login"]="Iniwura"
        with self.assertRaises(ProofError):
            receive(b,d)

    def test_bad_source_or_unsupported_comment_url_rejected(self):
        b=packet()
        for url in ("https://example.com/reviewer",
                    "http://github.com/Iniwura/falsum/issues/1#issuecomment-1",
                    "https://github.com/other/repo/issues/3#issuecomment-14"):
            with self.subTest(url=url):
                d=input_doc(b);d["reviews"]=[claim(b)]
                d["reviews"][0]["review_comment_url"]=url
                with self.assertRaises(ProofError):
                    receive(b,d)

    def test_preference_expertise_and_installed_version_not_fabricated(self):
        b=packet()
        for key,value in (("candidate_preference","ACCEPTED"),
                          ("version_evidence_status","VERIFIED"),
                          ("runtime_evidence_status","PRODUCTION_PROVEN"),
                          ("independent_reviewer_self_attested",False),
                          ("explanation","yes")):
            with self.subTest(key=key):
                d=input_doc(b);d["reviews"]=[claim(b)]
                d["reviews"][0][key]=value
                with self.assertRaises(ProofError):
                    receive(b,d)

    def test_multi_reviewer_disagreement_is_not_hidden(self):
        b=packet(); d=input_doc(b)
        a=claim(b);z=copy.deepcopy(a)
        z["reviewer_github_login"]="different-reviewer"
        z["review_comment_url"]="https://github.com/Iniwura/falsum/issues/88#issuecomment-45678"
        z["candidate_preference"]="B"
        d["reviews"]=[a,z]
        out=receive(b,d)
        self.assertEqual(out["unresolved_review_conflicts"],1)
        self.assertEqual(out["self_reported_reviewers_unique"],2)
        self.assertEqual(out["verified_independent_human_labels"],0)

    def test_spoofed_approved_packet_is_rejected(self):
        for field,value in (("label_status","INDEPENDENT_EXPERT_APPROVED"),
                            ("training_eligible",True),
                            ("official_network_eligible",True),
                            ("confirmed_exploit",True)):
            with self.subTest(field=field):
                b=packet();b["packets"][0][field]=value
                with self.assertRaises(ProofError):
                    receive(b,input_doc(b))


if __name__=="__main__":
    unittest.main()
