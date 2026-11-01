"""Phase3E: independent-source review materials are NOT approved network labels."""
import copy
import unittest

from falsum.phase2w_proof_gate import ProofError
from falsum.phase3a_external_sources import SOURCE_PINS, STATUS as CODE_STATUS
from falsum.phase3a_dependency_manifests import PINS as DEPS_PINS, STATUS as DEPS_STATUS
from falsum.phase3e_review_packets import STATUS, build


def fixtures():
    sources=[]
    for pin in SOURCE_PINS:
        id_,repo,commit,path,blob,values,lines=pin
        sources.append({
            "id":id_,"repository":repo,"commit":commit,"path":path,
            "source_git_blob_sha1":blob,"full_file_sha256":"a"*64,
            "source_code_executed":False,"external_runtime_tested":False,
            "dependency_version_proven":False,
            "static_router_calls":[{
                "line_start":line,"line_end":line+1,
                "observed_keyword_syntax":value,
                "call_ast_sha256":"b"*64,
                "receiver_identity_verified":False,
                "framework_version_verified":False,
                "call_executed":False,
                "applicability_conclusion":"UNRESOLVED_NO_DEPLOYMENT_OR_VERSION_PROOF",
            } for value,line in zip(values,lines)]
        })
    manifest=[]
    interpretations=(
        "DECLARATION_PERMITS_HISTORIC_AFFECTED_RANGE",
        "DECLARATION_EXCLUDES_HISTORIC_AFFECTED_RANGE",
        "DECLARATION_REQUIRES_AT_LEAST_FIXED",
        "DECLARATION_PERMITS_HISTORIC_AFFECTED_RANGE",
    )
    for pin,category in zip(DEPS_PINS,interpretations):
        id_,repo,commit,path,blob,kind,line,requirement,profile=pin
        manifest.append({
            "id":id_,"repository":repo,"commit":commit,
            "manifest_path":path,"manifest_git_blob_sha1":blob,
            "manifest_line":line,"declared_requirement":requirement,"profile":profile,
            "declared_historic_advisory_range":category,
            "is_installed_runtime_version":False,
            "is_deployed_application_version":False,
            "dependency_environment_resolved":False,
            "confirmed_vulnerability":False,
            "independent_expert_label":False,
        })
    source_report={
        "status":CODE_STATUS,"external_source_commits_and_blobs_verified":True,
        "source_executes_imports_or_applications":False,"network_eligible":False,
        "confirmed_vulnerabilities":0,"independent_expert_ground_truth_labels":0,
        "independent_external_project_count":3,"source_call_count":5,"cases":sources,
    }
    dependency_report={
        "status":DEPS_STATUS,"manifests_fetched_verified_without_installation":True,
        "third_party_application_executions":0,
        "actual_installed_or_deployed_versions_verified":0,
        "human_reviewed_labels":0,"network_eligible":False,
        "pinned_external_manifest_profiles":4,"profiles":manifest,
    }
    return source_report,dependency_report


class RealSourceReviewPacketTests(unittest.TestCase):
    def test_creates_exactly_five_independent_source_review_cases(self):
        s,d=fixtures()
        report=build(s,d)
        self.assertEqual(report["status"],STATUS)
        self.assertEqual(report["external_projects"],3)
        self.assertEqual(len(report["packets"]),5)
        self.assertEqual(len({x["packet_id"] for x in report["packets"]}),5)
        self.assertEqual(report["accepted_training_pairs"],0)
        self.assertEqual(report["independent_human_labels"],0)
        self.assertFalse(report["network_eligible"])
        self.assertTrue(report["phase3d_failed_model_not_converted_to_labels"])

    def test_all_five_link_to_pinned_external_source(self):
        s,d=fixtures()
        report=build(s,d)
        for item in report["packets"]:
            p=item["source"]
            self.assertIn("/blob/",p["view_url"])
            self.assertIn(p["commit"],p["view_url"])
            self.assertIn("#L"+str(p["line_start"]),p["view_url"])
            self.assertEqual(len(p["call_ast_sha256"]),64)
            self.assertEqual(len(p["whole_file_sha256"]),64)
            self.assertEqual(len(p["git_blob_sha1"]),40)
            self.assertTrue(item["review_question"])
            self.assertEqual(len(item["candidate_answers"]),2)
            self.assertEqual(len(item["candidate_answer_sha256"]),2)
            self.assertEqual(item["label_status"],"NOT_INDEPENDENTLY_ADJUDICATED")
            self.assertIsNone(item["reviewer_preference"])
            self.assertFalse(item["reviewer_identity_verified"])
            self.assertFalse(item["training_eligible"])
            self.assertFalse(item["official_network_eligible"])
            self.assertFalse(item["confirmed_exploit"])

    def test_nlweb_profiles_are_not_misrepresented_as_installed(self):
        s,d=fixtures()
        result=build(s,d)
        n=[x for x in result["packets"] if x["source"]["repository"]=="nlweb-ai/NLWeb"]
        self.assertEqual(len(n),2)
        for case in n:
            self.assertEqual(len(case["dependency_declarations"]),2)
            self.assertEqual({x["declared_requirement"] for x in case["dependency_declarations"]},
                             {"aiohttp>=3.13.5","aiohttp==3.13.3"})
            self.assertTrue(all(p["confirmed_actual_install"] is False
                                for p in case["dependency_declarations"]))
            self.assertIn("not the resolved version actually installed",case["review_question"])

    def test_perspective_true_is_not_cve_proof(self):
        s,d=fixtures()
        case=build(s,d)["packets"][0]
        self.assertEqual(case["source"]["observed_call_syntax"],"EXPLICIT_TRUE")
        self.assertIn("not the resolved version actually installed",case["review_question"])
        self.assertIn("no deployed package version",case["candidate_answers"][0]["text"])
        self.assertFalse(case["confirmed_exploit"])

    def test_maubot_omitted_must_not_be_promoted_to_safe(self):
        s,d=fixtures()
        case=build(s,d)["packets"][-1]
        self.assertEqual(case["source"]["observed_call_syntax"],"OMITTED_OPTION")
        self.assertIn("runtime default has not been verified",case["review_question"])
        self.assertFalse(case["training_eligible"])

    def test_forged_source_blob_and_sha_are_rejected(self):
        for field,value in (("source_git_blob_sha1","0"*40),
                            ("full_file_sha256","bad"),
                            ("repository","other/other"),
                            ("source_code_executed",True),
                            ("dependency_version_proven",True)):
            with self.subTest(field=field):
                s,d=fixtures()
                s["cases"][0][field]=value
                with self.assertRaises(ProofError):
                    build(s,d)

    def test_forged_verified_callee_or_actual_exploit_is_rejected(self):
        for field,value in (("receiver_identity_verified",True),
                            ("framework_version_verified",True),
                            ("call_executed",True),
                            ("observed_keyword_syntax","EXPLICIT_FALSE"),
                            ("call_ast_sha256","invalid")):
            with self.subTest(field=field):
                s,d=fixtures()
                s["cases"][0]["static_router_calls"][0][field]=value
                with self.assertRaises(ProofError):
                    build(s,d)

    def test_forged_installed_package_or_independent_label_rejected(self):
        for field,value in (("is_installed_runtime_version",True),
                            ("dependency_environment_resolved",True),
                            ("confirmed_vulnerability",True),
                            ("independent_expert_label",True),
                            ("declared_requirement","aiohttp==3.9.1")):
            with self.subTest(field=field):
                s,d=fixtures()
                d["profiles"][0][field]=value
                with self.assertRaises(ProofError):
                    build(s,d)

    def test_contradictory_network_readiness_rejected(self):
        for section,field,value in (
            ("source","network_eligible",True),
            ("source","confirmed_vulnerabilities",1),
            ("source","independent_expert_ground_truth_labels",1),
            ("manifest","network_eligible",True),
            ("manifest","actual_installed_or_deployed_versions_verified",1),
            ("manifest","human_reviewed_labels",1),
        ):
            with self.subTest(section=section,field=field):
                s,d=fixtures()
                (s if section=="source" else d)[field]=value
                with self.assertRaises(ProofError):
                    build(s,d)

    def test_source_identity_order_and_missing_case_rejected(self):
        s,d=fixtures()
        s["cases"]=s["cases"][1:]
        with self.assertRaises(ProofError):
            build(s,d)
        s,d=fixtures()
        s["cases"].reverse()
        with self.assertRaises(ProofError):
            build(s,d)

    def test_dependency_profile_swapping_rejected(self):
        s,d=fixtures()
        d["profiles"][1],d["profiles"][2]=d["profiles"][2],d["profiles"][1]
        with self.assertRaises(ProofError):
            build(s,d)
        s,d=fixtures()
        d["profiles"][0]["manifest_line"]=999
        with self.assertRaises(ProofError):
            build(s,d)

    def test_immutable_answer_hashes_cannot_match_if_answer_changes(self):
        s,d=fixtures()
        item=build(s,d)["packets"][0]
        self.assertNotEqual(item["candidate_answer_sha256"][0],item["candidate_answer_sha256"][1])
        self.assertEqual(len(item["candidate_answer_sha256"][0]),64)


if __name__=="__main__":
    unittest.main()
