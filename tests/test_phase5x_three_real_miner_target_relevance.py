"""Phase 5X: three actual public MINER source roles and fail-closed package controls.

Unit-test inputs below are deliberately *synthetic* and NEVER original paid
provider observations. Only the separate live original external Git SHA
verification job may report actual historical paid-status responses.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from falsum import phase5x_three_real_miner_target_relevance as x
from falsum.phase4l_external_receipt_evidence import git_blob_sha
from falsum.phase5m_real_source_sensitive_model import ROOT


def fake(role:str):
    req=({"intent":"SECURITY_REVIEW_GENERAL",
          "params":{"target":"npm package lodash version 4.17.15"}}
         if role=="canonical_routed_off_target" else
         {"method":"GET","endpoint":"/query",
          "payload":({"system":"npm","pkg":"lodash","ver":"4.17.15"}
                     if role=="direct_deps_dev_ghsa" else
                     {"pkg":"lodash","ver":"4.17.15"})})
    if role=="canonical_routed_off_target":
        body={"miner_id":"77003","result_shape":"raw",
              "result":[{"ghsa_id":f"GHSA-aaaa-bbbb-{i:04d}",
                         "description":"unrelated record"}
                        for i in range(100)]}
    elif role=="direct_deps_dev_ghsa":
        body={"miner_id":"190048","result_shape":"raw",
              "result":{
                  "versionKey":{"name":"lodash","system":"NPM","version":"4.17.15"},
                  "advisoryKeys":[{"id":f"GHSA-aaaa-bbbb-{i:04d}"} for i in range(6)]
              }}
    else:
        body={"miner_id":"77010","result_shape":"raw",
              "result":{
                  "package":{"name":"lodash","system":"NPM"},
                  "version":{"version":"4.17.15","advisories":[
                      {"aliases":[f"CVE-2026-{10000+i}"],"source":"OSV"}
                      for i in range(6)]}
              }}
    return {"request":req,"body":body}


class ThreeProviderOriginalCaptureContract(unittest.TestCase):
    def test_protocol_original_git_sha_and_three_different_transport_roles(self):
        policy=x.frozen()
        self.assertEqual(git_blob_sha((ROOT/x.LOCK).read_bytes()),x.FROZEN_BLOB)
        self.assertEqual(policy["source_git_commit"],x.ORIGINAL_SOURCE_COMMIT)
        self.assertEqual(policy["required_original_real_source_probes"],3)
        self.assertEqual(policy["negative_mutations_per_original"],4)
        self.assertEqual(policy["expected_constructed_adversarial_controls"],12)
        self.assertFalse(policy["all_external_responses_same_protocol_intent"])
        self.assertFalse(policy["all_external_requests_byte_identical"])
        self.assertFalse(policy["independent_miner_owners_verified"])
        self.assertEqual(policy["independent_appsec_gold_count"],0)
        self.assertFalse(policy["no_fair_same_canonical_intent_comparison_claim"] is False)

    def test_synthetic_target_relevance_contract_admits_two_not_three(self):
        verdicts={}
        for role in x.ROLES:
            doc=fake(role)
            verdicts[role]=x.classify(role,doc["request"],doc["body"])
        self.assertEqual(verdicts["canonical_routed_off_target"]["action"],
                         "DENY_UNSCOPED_SECURITY_ADVICE")
        self.assertEqual(verdicts["canonical_routed_off_target"]
                         ["reported_advisory_reference_count"],100)
        for role in ("direct_deps_dev_ghsa","direct_deps_dev_version"):
            self.assertEqual(verdicts[role]["action"],
                             "DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES")
            self.assertEqual(verdicts[role]["reported_advisory_reference_count"],6)
            self.assertTrue(verdicts[role]["no_auto_security_clearance"])
            self.assertTrue(verdicts[role]["not_fair_same_intent_comparison"])

    def test_all_12_original_role_mutations_must_deny_target_bound_display(self):
        p=x.frozen()
        self.assertEqual(len(p["local_synthetic_mutation_types"]),4)
        for role in x.ROLES:
            original=fake(role)
            for mutation in p["local_synthetic_mutation_types"]:
                altered=x._mutate(role,original,mutation)
                outcome=x.classify(role,altered["request"],altered["body"])
                with self.subTest(role=role,mutation=mutation):
                    self.assertNotEqual(
                        outcome["action"],
                        "DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES")

    def test_100_unscoped_ghsa_rows_still_deny_even_with_lodash_keyword_padding(self):
        d=fake("canonical_routed_off_target")
        d["body"]["result"][0]["description"]="lodash 4.17.15!"
        d["body"]["result"][-1]["package"]="lodash"
        result=x.classify("canonical_routed_off_target",d["request"],d["body"])
        self.assertEqual(result["action"],"DENY_UNSCOPED_SECURITY_ADVICE")

    def test_bad_or_nonexistent_package_version_in_direct_requests_denied(self):
        for role in x.ROLES[1:]:
            d=fake(role)
            for value in ("4.17.21","4.18.1",None,{"oops":1}):
                wrong=deepcopy(d)
                wrong["request"]["payload"]["ver"]=value
                with self.subTest(role=role,version=str(value)):
                    self.assertEqual(x.classify(role,wrong["request"],wrong["body"])
                                     ["action"],x.DENY)

    def test_unknown_source_role_must_throw_not_fall_through(self):
        d=fake("direct_deps_dev_ghsa")
        with self.assertRaises((x.TargetRelevanceError,ValueError)):
            x.classify("unregistered-miner",d["request"],d["body"])

    def test_direct_ghsa_duplicate_forged_or_missing_ids_denied(self):
        d=fake("direct_deps_dev_ghsa")
        bads=[]
        dup=deepcopy(d)
        dup["body"]["result"]["advisoryKeys"][0]=deepcopy(
            dup["body"]["result"]["advisoryKeys"][1])
        bads.append(dup)
        malformed=deepcopy(d)
        malformed["body"]["result"]["advisoryKeys"][0]["id"]="not-valid-ghsa"
        bads.append(malformed)
        missing=deepcopy(d)
        missing["body"]["result"]["advisoryKeys"].pop()
        bads.append(missing)
        for item in bads:
            self.assertEqual(x.classify("direct_deps_dev_ghsa",
                          item["request"],item["body"])["action"],x.DENY)

    def test_direct_osv_bad_source_or_duplicate_cve_denied(self):
        d=fake("direct_deps_dev_version")
        bads=[]
        bad=deepcopy(d)
        bad["body"]["result"]["version"]["advisories"][0]["source"]="NOT_OSV"
        bads.append(bad)
        duplicate=deepcopy(d)
        duplicate["body"]["result"]["version"]["advisories"][0]["aliases"]=[
            "CVE-2026-10001"]
        bads.append(duplicate)
        missing=deepcopy(d)
        missing["body"]["result"]["version"]["advisories"][0]["aliases"]=[]
        bads.append(missing)
        for item in bads:
            self.assertEqual(x.classify("direct_deps_dev_version",
                            item["request"],item["body"])["action"],x.DENY)

    def test_paid_status_never_auto_authorizes_security_clearance(self):
        for role in x.ROLES:
            d=fake(role)
            res=x.classify(role,d["request"],d["body"])
            self.assertTrue(res["no_auto_security_clearance"])
            self.assertTrue(res["not_independent_advisory_accuracy_gold"])
            self.assertFalse(res["registered_network_evaluator"])
            self.assertFalse(res["real_miner_ranking_improved"])

    def test_unknown_content_or_misnamed_miners_fail_closed(self):
        for role in x.ROLES:
            d=fake(role)
            for body in (None,[],{"miner_id":"wrong"},{}):
                with self.subTest(role=role):
                    self.assertEqual(x.classify(role,d["request"],body)["action"],x.DENY)

    def test_file_byte_modification_cannot_change_frozen_case_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            file=root/x.LOCK
            file.parent.mkdir(parents=True)
            file.write_bytes((ROOT/x.LOCK).read_bytes()+b" ")
            with self.assertRaises(x.TargetRelevanceError):
                x.frozen(root)


if __name__=="__main__":
    unittest.main()
