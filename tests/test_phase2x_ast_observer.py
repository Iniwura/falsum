"""Phase 2X: independent AST syntactic evidence, refusal to promote to exploit proof."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.phase2w_proof_gate import ProofError, evaluate_case, validate_catalog
from falsum.phase2w_capture import capture_claims
from falsum.phase2x_ast_observer import observe, STATUS
from falsum.phase2x_reconcile import reconcile
from test_phase2w_proof_gate import inputs


class ScopedASTTests(unittest.TestCase):
    def setUp(self):
        self.catalog,self.sources=inputs()
        self.rules=validate_catalog(self.catalog,self.sources)
        self.td=tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root=Path(self.td.name)
        self.path=self.root/"app.py"

    def _write(self,text):
        self.path.write_text(text,encoding="utf-8")
        return text

    def _obs(self,case):
        return observe(self.catalog,self.sources,case,self.root,["app.py"])

    def _claim(self,case,req,claim,line=1):
        m=capture_claims(self.rules[case],self.root,[{
            "requirement_id":req,"claim":claim,
            "path":"app.py","line_start":line,"line_end":line}])
        return {"schema_version":1,"status":"UNREVIEWED_APPLICATION_EVIDENCE_BATCH",
                "research_only":True,"scenarios":[m]}

    def test_literal_false_aiohttp_is_exact_syntax_not_global_safety(self):
        self._write('app.router.add_static("/assets", "./public", follow_symlinks=False)\n')
        out=self._obs("real-aiohttp-static-traversal")
        self.assertEqual(out["status"],STATUS)
        self.assertEqual(len(out["observations"]),1)
        row=out["observations"][0]
        self.assertEqual(row["observation"],"EXPLICIT_FALSE")
        self.assertEqual(row["syntactic_implication"],"SYNTACTIC_ABSENT")
        self.assertFalse(row["callee_identity_verified"])
        self.assertFalse(row["call_execution_verified"])
        self.assertFalse(row["application_wide_absence_proven"])
        self.assertFalse(out["network_eligible"])
        self.assertFalse(out["version_reachability_or_alias_binding_proven"])

    def test_literal_true_and_dynamically_configured_paths(self):
        for expr,kind,state in [
            ("True","EXPLICIT_TRUE","SYNTACTIC_PRESENT"),
            ("False","EXPLICIT_FALSE","SYNTACTIC_ABSENT"),
            ("config.follow_symlinks","DYNAMIC_OR_NONBOOLEAN_FLAG","UNDETERMINED"),
            ("1","DYNAMIC_OR_NONBOOLEAN_FLAG","UNDETERMINED"),
            ("None","DYNAMIC_OR_NONBOOLEAN_FLAG","UNDETERMINED"),
        ]:
            with self.subTest(expr=expr):
                self._write('app.router.add_static("/x", path, follow_symlinks='+expr+')\n')
                found=self._obs("real-aiohttp-static-traversal")["observations"]
                self.assertEqual(len(found),1)
                self.assertEqual((found[0]["observation"],found[0]["syntactic_implication"]),
                                 (kind,state))

    def test_missing_keyword_and_unpacking_must_abstain(self):
        for expr,expected in [
            ('app.router.add_static("/x", path)',"KEYWORD_NOT_EXPLICIT"),
            ('app.router.add_static("/x", path, follow_symlinks=True, **opts)',
             "KWARG_EXPANSION_UNRESOLVED")
        ]:
            with self.subTest(expr=expr):
                self._write(expr+"\n")
                observation=self._obs("real-aiohttp-static-traversal")["observations"][0]
                self.assertEqual(observation["observation"],expected)
                self.assertEqual(observation["syntactic_implication"],"UNDETERMINED")

    def test_no_recognized_call_is_not_evidence_of_absence(self):
        self._write("other.add_static('/x',path,follow_symlinks=False)\n")
        out=self._obs("real-aiohttp-static-traversal")
        self.assertEqual(out["observations"],[])

    def test_keyword_false_on_fake_router_is_not_proof_of_binding(self):
        self._write("dummy.router.add_static('/x',path,follow_symlinks=False)\n")
        out=self._obs("real-aiohttp-static-traversal")["observations"][0]
        self.assertFalse(out["callee_identity_verified"])
        self.assertFalse(out["call_execution_verified"])

    def test_tornado_literal_integer_is_only_local_argument_fact(self):
        for expr,expected,implication in [
            ("3600","EXPLICIT_INT_MAX_AGE","SYNTACTIC_ABSENT"),
            ("-1","EXPLICIT_INT_MAX_AGE","SYNTACTIC_ABSENT"),
            ("'3600'","EXPLICIT_NONINTEGER_LITERAL_NOT_PROVEN_UNTRUSTED","UNDETERMINED"),
            ("request.args['max_age']","DYNAMIC_MAX_AGE_UNRESOLVED","UNDETERMINED"),
        ]:
            with self.subTest(expr=expr):
                self._write("self.set_cookie('x','y',max_age="+expr+")\n")
                o=self._obs("fresh-tornado-cookie-attribute")["observations"][0]
                self.assertEqual((o["observation"],o["syntactic_implication"]),(expected,implication))
                self.assertFalse(o["application_wide_absence_proven"])

    def test_websockets_compression_declaration_and_dynamic_abstention(self):
        for arg,expected,state in [
            ("None","EXPLICIT_COMPRESSION_NONE","SYNTACTIC_ABSENT"),
            ('"deflate"',"EXPLICIT_DEFLATE_ENABLED_NEGOTIATION_UNPROVEN","UNDETERMINED"),
            ("settings.compression","DYNAMIC_COMPRESSION_UNRESOLVED","UNDETERMINED"),
        ]:
            with self.subTest(arg=arg):
                self._write("websockets.serve(handler, 'localhost', 8765, compression="+arg+")\n")
                out=self._obs("fresh-websockets-deflate-limit")["observations"][0]
                self.assertEqual((out["observation"],out["syntactic_implication"]),(expected,state))
                self.assertFalse(out["call_execution_verified"])

    def test_unqualified_serve_is_not_assumed_to_be_websockets(self):
        self._write("serve(handler,'localhost',8765,compression=None)\n")
        self.assertEqual(self._obs("fresh-websockets-deflate-limit")["observations"],[])

    def test_source_sha_is_bound_to_full_application_file(self):
        self._write("app.router.add_static('/x',path,follow_symlinks=True)\n")
        a=self._obs("real-aiohttp-static-traversal")
        self._write("app.router.add_static('/x',path,follow_symlinks=False)\n")
        b=self._obs("real-aiohttp-static-traversal")
        self.assertNotEqual(a["scanned_files"][0]["sha256"],b["scanned_files"][0]["sha256"])
        self.assertNotEqual(a["observations"][0]["call_ast_sha256"],b["observations"][0]["call_ast_sha256"])

    def test_symlink_path_escape_and_wrong_file_type_refused(self):
        self._write("app.router.add_static('/x',path,follow_symlinks=False)\n")
        (self.root/"alias.py").symlink_to(self.path)
        for path in ("alias.py","../outside.py","/tmp/app.py","app.txt"):
            with self.subTest(path=path):
                with self.assertRaises((ProofError,OSError)):
                    self._obs_with_paths([path])

    def _obs_with_paths(self,paths):
        return observe(self.catalog,self.sources,"real-aiohttp-static-traversal",self.root,paths)

    def test_duplicate_paths_and_invalid_or_oversized_file_refused(self):
        self._write("app.router.add_static('/x',path,follow_symlinks=False)\n")
        with self.assertRaises(ProofError):
            self._obs_with_paths(["app.py","app.py"])
        (self.root/"huge.py").write_bytes(b"x"*128001)
        with self.assertRaises(ProofError):
            self._obs_with_paths(["huge.py"])
        (self.root/"invalid.py").write_bytes(b"\xff")
        with self.assertRaises(ProofError):
            self._obs_with_paths(["invalid.py"])

    def test_invalid_syntax_fails_closed_not_silently_ignored(self):
        self._write("app.router.add_static('/x',\n")
        with self.assertRaisesRegex(ProofError,"malformed Python"):
            self._obs("real-aiohttp-static-traversal")

    def test_out_of_scope_source_rule_rejected(self):
        self._write("self.set_cookie('x','y',max_age=3600)\n")
        with self.assertRaisesRegex(ProofError,"only supports three"):
            self._obs("real-requests-proxy-auth")

    def test_conflicting_developer_statement_is_flagged_but_not_labeled(self):
        self._write("app.router.add_static('/x', path, follow_symlinks=False)\n")
        batch=self._claim("real-aiohttp-static-traversal","follow_symlinks_enabled","present")
        ast=self._obs("real-aiohttp-static-traversal")
        result=reconcile(self.catalog,self.sources,batch,self.root,[ast])
        self.assertEqual(result["ast_contradictions_found"],1)
        self.assertEqual(result["ast_syntactic_agreements_found"],0)
        self.assertEqual(result["cases"][0]["reconciled_status"],
                         "BLOCKED_AST_SYNTAX_CONFLICT_REQUIRES_HUMAN_REVIEW")
        self.assertEqual(result["cases"][0]["original_unreviewed_result"],
                         "INSUFFICIENT_APPLICATION_EVIDENCE")
        self.assertFalse(result["actual_app_security_semantics_verified"])
        self.assertEqual(result["verified_exploits"],0)
        self.assertFalse(result["network_eligible"])
        self.assertEqual(result["human_approved_labels"],0)

    def test_consistent_literal_syntax_does_not_promote_to_verified_exploit(self):
        self._write("app.router.add_static('/x', path, follow_symlinks=False)\n")
        batch=self._claim("real-aiohttp-static-traversal","follow_symlinks_enabled","absent")
        ast=self._obs("real-aiohttp-static-traversal")
        result=reconcile(self.catalog,self.sources,batch,self.root,[ast])
        self.assertEqual(result["ast_syntactic_agreements_found"],1)
        self.assertEqual(result["ast_contradictions_found"],0)
        self.assertEqual(result["cases"][0]["reconciled_status"],"UNREVIEWED_ORIGINAL_RESULT_NOT_PROMOTED")
        self.assertFalse(result["cases"][0]["verified_actual_runtime_applicability"])

    def test_dynamic_call_does_not_claim_present_or_absent(self):
        self._write("app.router.add_static('/x', path, follow_symlinks=config.flag)\n")
        batch=self._claim("real-aiohttp-static-traversal","follow_symlinks_enabled","present")
        ast=self._obs("real-aiohttp-static-traversal")
        x=reconcile(self.catalog,self.sources,batch,self.root,[ast])
        self.assertEqual(x["ast_contradictions_found"],0)
        self.assertEqual(x["ast_syntactic_agreements_found"],0)
        self.assertEqual(x["cases"][0]["citation_reconciliation"][0]["consistency"],
                         "AST_DYNAMIC_OR_UNRESOLVED")

    def test_ast_packet_forgery_detected_via_recomputation(self):
        self._write("app.router.add_static('/x', path, follow_symlinks=False)\n")
        batch=self._claim("real-aiohttp-static-traversal","follow_symlinks_enabled","present")
        ast=self._obs("real-aiohttp-static-traversal")
        tampered=copy.deepcopy(ast)
        tampered["observations"][0]["syntactic_implication"]="SYNTACTIC_PRESENT"
        with self.assertRaisesRegex(ProofError,"did not reproduce"):
            reconcile(self.catalog,self.sources,batch,self.root,[tampered])

    def test_application_changed_since_ast_capture_aborts(self):
        self._write("app.router.add_static('/x', path, follow_symlinks=False)\n")
        batch=self._claim("real-aiohttp-static-traversal","follow_symlinks_enabled","present")
        ast=self._obs("real-aiohttp-static-traversal")
        self._write("app.router.add_static('/x', path, follow_symlinks=True)\n")
        with self.assertRaises(ProofError):
            reconcile(self.catalog,self.sources,batch,self.root,[ast])

    def test_ast_observation_other_file_does_not_contradict_unrelated_line(self):
        self._write("flag=True\napp.router.add_static('/x', path, follow_symlinks=False)\n")
        batch=self._claim("real-aiohttp-static-traversal","follow_symlinks_enabled","present",line=1)
        ast=self._obs("real-aiohttp-static-traversal")
        score=reconcile(self.catalog,self.sources,batch,self.root,[ast])
        self.assertEqual(score["cases"][0]["matched_ast_call_citations"],0)
        self.assertEqual(score["ast_contradictions_found"],0)

    def test_malicious_status_promotion_in_ast_report_rejected(self):
        self._write("app.router.add_static('/x',path,follow_symlinks=True)\n")
        batch=self._claim("real-aiohttp-static-traversal","follow_symlinks_enabled","present")
        ast=self._obs("real-aiohttp-static-traversal")
        for key,value in (("network_eligible",True),("human_reviewed",True),
                          ("automatically_verified_exploit_preconditions",1)):
            with self.subTest(key=key):
                packet=copy.deepcopy(ast)
                packet[key]=value
                with self.assertRaises(ProofError):
                    reconcile(self.catalog,self.sources,batch,self.root,[packet])


if __name__=="__main__":
    unittest.main()
