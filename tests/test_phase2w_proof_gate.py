"""Phase 2W offline adversarial proof-gate tests with explicit synthetic provenance."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from falsum.phase2w_proof_gate import (
    INPUT_STATUS, REPORT_STATUS, ProofError, evaluate_batch,
    evaluate_case, validate_catalog, verify_excerpt,
)
from falsum.phase2w_synthetic_demo import generate
from falsum.real_fix_corpus import load_queue

ROOT=Path(__file__).resolve().parents[1]


def inputs():
    rules=json.loads((ROOT/"data/phase2w-applicability-rules.json").read_text())
    fresh=json.loads((ROOT/"data/phase2u-fresh-transfer-cases.json").read_text())
    original=load_queue(ROOT/"data/real-fix-queue.json")
    train=load_queue(ROOT/"data/real-fix-train-candidates.json")
    sources=original["cases"]+train["cases"]+fresh["cases"]
    return rules,sources


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.catalog,self.sources=inputs()
        self.td=tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root=Path(self.td.name)/"evidence"
        self.batch=generate(self.catalog,self.sources,self.root)
        self.rules=validate_catalog(self.catalog,self.sources)

    def test_all_eleven_source_families_are_pinned(self):
        self.assertEqual(len(self.rules),11)
        self.assertEqual(len(self.sources),11)
        self.assertEqual(sum(len(r["requirements"]) for r in self.rules.values()),22)
        self.assertTrue(all(len(r["source_commit"])==40 for r in self.rules.values()))

    def test_four_explicit_states_for_every_case(self):
        report=evaluate_batch(self.catalog,self.sources,self.batch,self.root)
        self.assertEqual(report["status"],REPORT_STATUS)
        self.assertEqual(len(report["results"]),44)
        self.assertEqual(set(report["counts"].values()),{11})
        self.assertEqual(report["confirmed_exploits"],0)
        self.assertEqual(report["accepted_evaluation_labels"],0)
        self.assertFalse(report["source_replayed_in_this_call"])
        self.assertFalse(report["application_assertions_independently_verified"])
        self.assertFalse(report["network_eligible"])
        for r in report["results"]:
            self.assertTrue(r["human_review_required"])
            self.assertFalse(r["confirmed_security_finding"])
            self.assertFalse(r["actual_application_semantics_verified"])
            self.assertTrue(all("sha256" in cite for p in r["preconditions"] for cite in p["citations"]))
            self.assertEqual(r["application_evidence_origin"],"synthetic_fixture")

    def test_no_evidence_is_unknown_not_safe(self):
        rule=self.rules[self.sources[0]["id"]]
        manifest={"schema_version":1,"status":INPUT_STATUS,"case_id":rule["case_id"],
                  "repository":rule["repository"],"source_commit":rule["source_commit"],
                  "evidence_origin":"unreviewed_application_submission","evidence":[]}
        result=evaluate_case(rule,manifest,self.root)
        self.assertEqual(result["result"],"INSUFFICIENT_APPLICATION_EVIDENCE")
        self.assertEqual(result["machine_integrity_verified_excerpts"],0)

    def test_all_asserted_conditions_are_only_candidate_never_confirmed(self):
        m=self.batch["scenarios"][0]
        r=evaluate_case(self.rules[m["case_id"]],m,self.root)
        self.assertEqual(r["result"],"CONDITIONALLY_APPLICABLE_REVIEW_CANDIDATE")
        self.assertFalse(r["confirmed_security_finding"])
        self.assertFalse(r["evidence_proves_exploitation"])

    def test_absent_condition_blocks_candidate(self):
        m=self.batch["scenarios"][1]
        r=evaluate_case(self.rules[m["case_id"]],m,self.root)
        self.assertEqual(r["result"],"APPLICABILITY_PRECONDITION_CONTRADICTED")
        self.assertIn("ASSERTED_ABSENT",[x["evidence_state"] for x in r["preconditions"]])

    def test_unknown_condition_does_not_get_negative_label(self):
        m=self.batch["scenarios"][2]
        r=evaluate_case(self.rules[m["case_id"]],m,self.root)
        self.assertEqual(r["result"],"INSUFFICIENT_APPLICATION_EVIDENCE")
        self.assertIn("UNOBSERVED",[x["evidence_state"] for x in r["preconditions"]])

    def test_conflicting_claims_override_other_conditions(self):
        m=self.batch["scenarios"][3]
        r=evaluate_case(self.rules[m["case_id"]],m,self.root)
        self.assertEqual(r["result"],"CONFLICTING_APPLICATION_CLAIMS")
        self.assertEqual(r["preconditions"][0]["evidence_state"],"CONFLICT")

    def test_tampered_application_file_rejected_even_with_plausible_quote(self):
        m=copy.deepcopy(self.batch["scenarios"][0])
        path=self.root/m["evidence"][0]["path"]
        path.write_bytes(path.read_bytes()+b"tampered\n")
        with self.assertRaisesRegex(ProofError,"changed"):
            evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_forged_excerpt_rejected_even_with_exact_file_hash(self):
        m=copy.deepcopy(self.batch["scenarios"][0])
        m["evidence"][0]["quote"]="SIMULATED CLAIM: trust me"
        with self.assertRaisesRegex(ProofError,"exact cited"):
            evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_wrong_line_range_and_bool_indices_fail_closed(self):
        for start,end in ((0,1),(5,4),(True,1),(1,100),(2,2)):
            with self.subTest(start=start,end=end):
                m=copy.deepcopy(self.batch["scenarios"][0])
                m["evidence"][0]["line_start"]=start
                m["evidence"][0]["line_end"]=end
                with self.assertRaises(ProofError):
                    evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_path_traversal_and_absolute_source_path_refused(self):
        for path in ("../outside","/etc/passwd","data//bad.txt","a/../../secret","./bad","dir\\escape.txt"):
            with self.subTest(path=path):
                m=copy.deepcopy(self.batch["scenarios"][0])
                m["evidence"][0]["path"]=path
                with self.assertRaises(ProofError):
                    evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_symlink_refused_even_if_target_inside_root(self):
        m=copy.deepcopy(self.batch["scenarios"][0])
        src=self.root/m["evidence"][0]["path"]
        target=src.with_name("link.txt")
        target.symlink_to(src)
        m["evidence"][0]["path"]=str(target.relative_to(self.root))
        with self.assertRaisesRegex(ProofError,"symlink"):
            evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_wrong_repository_or_source_commit_rejected(self):
        for key,new in (("repository","attacker/fork"),("source_commit","1"*40),
                        ("evidence_origin","independently_expert_approved"),
                        ("status","NETWORK_APPROVED")):
            with self.subTest(field=key):
                m=copy.deepcopy(self.batch["scenarios"][0])
                m[key]=new
                with self.assertRaises(ProofError):
                    evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_catalog_cannot_change_real_upstream_source_blob(self):
        rule=copy.deepcopy(self.catalog)
        rule["rules"][0]["source_blob"]="f"*40
        with self.assertRaisesRegex(ProofError,"source_blob"):
            validate_catalog(rule,self.sources)

    def test_rule_cannot_promote_human_review_or_network(self):
        for field,val in (("independent_human_reviews",1),("network_eligible",True),
                          ("research_only",False),("status","READY_TO_WIN")):
            with self.subTest(field=field):
                rule=copy.deepcopy(self.catalog);rule[field]=val
                with self.assertRaises(ProofError):
                    validate_catalog(rule,self.sources)

    def test_unknown_evidence_requirement_rejected(self):
        m=copy.deepcopy(self.batch["scenarios"][0])
        m["evidence"][0]["requirement_id"]="invented_exploit"
        with self.assertRaisesRegex(ProofError,"out-of-catalog"):
            evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_evidence_unknown_keys_refused(self):
        m=copy.deepcopy(self.batch["scenarios"][0])
        m["evidence"][0]["expert_approved"]=True
        with self.assertRaisesRegex(ProofError,"unexpected evidence"):
            evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_invalid_research_status_refused(self):
        p=copy.deepcopy(self.batch)
        p["research_only"]=False
        with self.assertRaisesRegex(ProofError,"invalid batch"):
            evaluate_batch(self.catalog,self.sources,p,self.root)

    def test_source_type_is_not_self_attested(self):
        m=copy.deepcopy(self.batch["scenarios"][0])
        m["source_verified"]=True
        with self.assertRaisesRegex(ProofError,"trust designation mismatch"):
            evaluate_case(self.rules[m["case_id"]],m,self.root)

    def test_oversize_evidence_file_rejected(self):
        m=copy.deepcopy(self.batch["scenarios"][0])
        p=self.root/m["evidence"][0]["path"]
        p.write_bytes(b"x"*128001)
        m["evidence"][0]["sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ProofError,"bounded evidence size"):
            evaluate_case(self.rules[m["case_id"]],m,self.root)


if __name__=="__main__":
    unittest.main()
