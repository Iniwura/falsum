"""Adversarial verification of real historical JS source execution receipt semantics."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from falsum import phase5v_historical_runtime_verifier as v
from falsum.phase5m_real_source_sensitive_model import ROOT


def synthetic_reports():
    """Only local unit-test doubles, NEVER called original runtime evidence."""
    out=[]
    for case in v.frozen()["projects"]:
        for role in ("affected","fixed"):
            unsafe=role=="affected"
            out.append({
                "schema_version":1,
                "status":v.REPORT_STATUS,
                "project":case["key"],
                "original_source_revision_role":role,
                "original_git_commit":case[role+"_commit"],
                "original_source_git_blob_sha1":case[role+"_blob"],
                "original_upstream_test_git_blob_sha1":case[role+"_test_blob"],
                "historical_original_source_executed_in_node":True,
                "historical_upstream_test_file_authenticated_elsewhere":True,
                "full_original_upstream_suite_executed":False,
                "unrelated_safe_control_passed":True,
                "unsafe_observed":unsafe,
                "expected_unsafe_observation":unsafe,
                "reproduces_frozen_affected_to_fixed_behavior":True,
                "local_loopback_only_if_redirect":case["key"]==
                    "follow-redirects-custom-headers",
                "no_remote_vulnerability_probe":True,
                "no_independent_expert_gold":True,
                "no_real_telegraph_network_calls":True,
                "no_registered_evaluator":True,
            })
    return out


class HistoricalRuntimeReceiptsContract(unittest.TestCase):
    def test_pinned_original_protocol_exists_before_runtime(self):
        p=v.frozen()
        self.assertEqual(v.git_blob((ROOT/v.LOCK).read_bytes()),
                         v.ORIGINAL_GIT_BLOB_SHA1)
        self.assertEqual(len(p["projects"]),4)
        self.assertEqual(p["expected_original_historical_local_forward_probes"],8)
        self.assertEqual(p["expected_distinct_historical_source_reversals"],4)
        self.assertEqual(p["explicit_unverified"]["independent_expert_gold"],0)
        self.assertFalse(p["explicit_unverified"]["full_original_upstream_test_suite_rerun"])
        self.assertTrue(p["projects"][0]["expected_affected_unsafe"])
        self.assertFalse(p["projects"][0]["expected_fixed_unsafe"])

    def test_synthetic_ideal_report_would_be_accepted_but_not_actual_evidence(self):
        result=v.verify(synthetic_reports())
        self.assertEqual(result["focused_original_historical_source_behavior_reversals"],4)
        self.assertEqual(result["original_git_commits_executed_in_isolated_node"],8)
        self.assertFalse(result["original_upstream_full_test_suites_executed"])
        self.assertEqual(result["independent_expert_gold_count"],0)
        self.assertFalse(result["same_request_real_miner_ranking_improved"])
        self.assertFalse(result["falsum_external_adoption"])

    def test_missing_duplicate_wrong_revision_or_borrowed_git_hash_rejected(self):
        initial=synthetic_reports()
        variants=[]
        shortened=deepcopy(initial);shortened.pop();variants.append(shortened)
        duplicate=deepcopy(initial);duplicate[-1]=deepcopy(duplicate[0]);variants.append(duplicate)
        unknown=deepcopy(initial);unknown[0]["project"]="fabricated";variants.append(unknown)
        wrong_sha=deepcopy(initial);wrong_sha[0]["original_git_commit"]="a"*40;variants.append(wrong_sha)
        wrong_blob=deepcopy(initial);wrong_blob[0]["original_upstream_test_git_blob_sha1"]="b"*40;variants.append(wrong_blob)
        swapped=deepcopy(initial);swapped[0]["original_source_revision_role"]="fixed";variants.append(swapped)
        bad_control=deepcopy(initial);bad_control[0]["unrelated_safe_control_passed"]=False;variants.append(bad_control)
        untrue=deepcopy(initial);untrue[0]["unsafe_observed"]=False;variants.append(untrue)
        fake=deepcopy(initial);fake[0]["historical_original_source_executed_in_node"]=False;variants.append(fake)
        parsed=deepcopy(initial);parsed[0]["unsafe_observed"]="true";variants.append(parsed)
        unknown_extra=deepcopy(initial);unknown_extra[0]["human_gold_certified"]=True;variants.append(unknown_extra)
        suite=deepcopy(initial);suite[0]["full_original_upstream_suite_executed"]=True;variants.append(suite)
        registered=deepcopy(initial);registered[0]["no_registered_evaluator"]=False;variants.append(registered)
        no_network=deepcopy(initial);no_network[0]["no_real_telegraph_network_calls"]=False;variants.append(no_network)
        for bad in variants:
            with self.subTest(str(bad[0].get("project"))):
                with self.assertRaises((v.RuntimeProofError,ValueError)):
                    v.verify(bad)

    def test_no_backward_unsafe_and_rerun_authentication(self):
        x=synthetic_reports()
        fixed=next(a for a in x if a["original_source_revision_role"]=="fixed")
        fixed["unsafe_observed"]=True
        with self.assertRaises(v.RuntimeProofError):
            v.verify(x)

    def test_freeze_byte_mutation_blocks_historical_claims(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            target=root/v.LOCK
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes((ROOT/v.LOCK).read_bytes()+b"\n")
            with self.assertRaises(v.RuntimeProofError):
                v.frozen(root)


if __name__=="__main__":
    unittest.main()
