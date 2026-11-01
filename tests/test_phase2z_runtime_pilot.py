"""Phase 2Z: deny arbitrary user-code execution and fabricated runtime/provenance."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.phase2w_proof_gate import ProofError
from falsum.phase2z_runtime_pilot import (
    ALLOWED, CASE, VERSION, STATUS, validate_contract, reconcile_observations,
)

ROOT=Path(__file__).resolve().parents[1]


def spec():
    return json.loads((ROOT/"data/phase2z-aiohttp-pilot-contract.json").read_text())


def sample_report():
    rows=spec()["fixtures"]
    return {"results":[{
        "fixture":r["name"],"static_source_keyword":r["expected_syntax"],
        "runtime_registered_follow_symlinks":r["expected_runtime_flag"],
        "loopback_public_http_status":200,"loopback_missing_http_status":404,
        "runtime_bound_to_installed_aiohttp":True,
        "runtime_route_source_and_static_hash_match":True,
        "actual_exploit_reproduced":False
    } for r in rows]}


class PilotTrustBoundaryTests(unittest.TestCase):
    def test_exact_package_and_three_allowlisted_modules(self):
        rows=validate_contract(spec())
        self.assertEqual(VERSION,"3.10.11")
        self.assertEqual(CASE,"real-aiohttp-static-traversal")
        self.assertEqual(len(rows),3)
        self.assertEqual([r["module"] for r in rows],[x[1] for x in ALLOWED])
        self.assertEqual([r["expected_syntax"] for r in rows],
                         ["SYNTACTIC_ABSENT","SYNTACTIC_PRESENT","UNDETERMINED"])

    def test_version_substitution_and_affected_version_refused(self):
        for value in ("3.8.6","3.9.1","3.9.2","latest","3.11.11"):
            with self.subTest(value=value):
                d=spec();d["installed_version"]=value
                with self.assertRaises(ProofError):
                    validate_contract(d)

    def test_never_import_arbitrary_user_repo_module(self):
        for path in ("random.third_party.application","os","subprocess"):
            with self.subTest(path=path):
                d=spec();d["fixtures"][0]["module"]=path
                with self.assertRaises(ProofError):
                    validate_contract(d)

    def test_module_allowlist_tampering_rejected(self):
        d=spec();d["only_allowed_python_modules"].append("my_private_code")
        with self.assertRaises(ProofError):
            validate_contract(d)

    def test_fabricated_vulnerability_or_network_acceptance_refused(self):
        for field,bad in (("live_vulnerabilities_confirmed",1),
                          ("independent_human_reviews",1),
                          ("network_eligible",True),
                          ("status","READY_FOR_NETWORK")):
            with self.subTest(field=field):
                d=spec();d[field]=bad
                with self.assertRaises(ProofError):
                    validate_contract(d)

    def test_reconcile_rejects_false_runtime_flag(self):
        r=sample_report();r["results"][1]["runtime_registered_follow_symlinks"]=False
        with self.assertRaisesRegex(ProofError,"does not match"):
            reconcile_observations(r,validate_contract(spec()))

    def test_dynamic_syntax_must_remain_undetermined(self):
        r=sample_report();r["results"][2]["static_source_keyword"]="SYNTACTIC_ABSENT"
        with self.assertRaisesRegex(ProofError,"does not match"):
            reconcile_observations(r,validate_contract(spec()))

    def test_wrong_http_status_cannot_be_ignored(self):
        r=sample_report();r["results"][0]["loopback_public_http_status"]=500
        with self.assertRaises(ProofError):
            reconcile_observations(r,validate_contract(spec()))

    def test_exploit_claim_rejected_even_when_http_tests_pass(self):
        r=sample_report();r["results"][0]["actual_exploit_reproduced"]=True
        with self.assertRaises(ProofError):
            reconcile_observations(r,validate_contract(spec()))

    def test_good_runtime_shape_is_not_security_accuracy(self):
        out=reconcile_observations(sample_report(),validate_contract(spec()))
        self.assertEqual(out["scenarios"],3)
        self.assertEqual(out["runtime_routes_verified"],3)
        self.assertEqual(out["literal_static_flag_correspondences"],2)
        self.assertEqual(out["dynamic_config_static_abstentions"],1)
        self.assertEqual(out["actual_exploits_reproduced"],0)

    def test_unexpected_module_order_or_fields_refused(self):
        d=spec();d["fixtures"]=list(reversed(d["fixtures"]))
        with self.assertRaises(ProofError):
            validate_contract(d)
        d=spec();d["fixtures"][0]["expert_approved"]=True
        with self.assertRaises(ProofError):
            validate_contract(d)

    def test_no_allowlist_source_overwrite(self):
        self.assertEqual(len(ALLOWED),3)
        self.assertTrue(all(r[2].startswith("examples/phase2z_runtime_pilot/") for r in ALLOWED))


if __name__=="__main__":
    unittest.main()
