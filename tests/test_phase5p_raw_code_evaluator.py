"""Phase 5P: offline anti-shortcut and provenance tests; no fake model results."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5p_raw_code_evaluator as m
from falsum.phase5m_real_source_sensitive_model import ROOT, DiagnosticError


class AuthenticatedRawSourceEvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.protocol,cls.lock=m.frozen()

    def test_original_prestudy_identity_model_and_zero_gold(self):
        self.assertEqual(m.git_blob((ROOT/m.PROTOCOL).read_bytes()),m.PROTOCOL_BLOB)
        self.assertEqual(m.git_blob((ROOT/m.SOURCE_LOCK).read_bytes()),m.SOURCE_BLOB)
        self.assertEqual(tuple(x["key"] for x in self.lock["cases"]),m.PROJECTS)
        self.assertEqual(self.protocol["total_tasks"],12)
        self.assertTrue(self.protocol["programmatic_excerpts_instead_of_model_summaries"])
        self.assertTrue(self.protocol["no_independent_human_expert_gold"])
        self.assertTrue(self.protocol["no_registered_telegraph_evaluator"])
        self.assertTrue(self.protocol["no_external_developer_adoption"])
        self.assertTrue(self.protocol["no_official_h2_entry_submitted"])

    def test_excerpt_requires_one_real_anchor_and_rejects_ambiguous(self):
        source="a\nb\nexcept ValueError as e:\n    raise X\nreturn None\n"
        self.assertIn("raise X",m.excerpt(source,"except ValueError as e:",[-2,2]))
        with self.assertRaises(DiagnosticError):
            m.excerpt(source,"def malicious_missing",[-1,2])
        with self.assertRaises(DiagnosticError):
            m.excerpt(source+"except ValueError as e:\n",
                      "except ValueError as e:",[-1,2])
        with self.assertRaises(DiagnosticError):
            m.excerpt(source,"except ValueError as e:",[-1,2],
                      extra_anchor="nonexistent",extra_window=[-1,2])

    def test_pin_fail_closed_for_upstream_source_bytes_and_repo(self):
        row=deepcopy(self.lock["cases"][0])
        def fake_download(url):
            self.assertTrue(url.startswith("https://raw.githubusercontent.com/jpadilla/pyjwt/"))
            return b"def _decode_payload(self):\n    pass\n"
        with self.assertRaises(DiagnosticError):
            m._source_for(row,"parent",fake_download)
        row["repository"]="untrusted/fork"
        with self.assertRaises(DiagnosticError):
            m._source_for(row,"parent",fake_download)

    def test_strict_template_and_order(self):
        fake={"questions":[{"id":m.ident(k,c)}
              for k in m.PROJECTS for c in m.CONDITIONS]}
        template=m.response_template(fake)
        self.assertTrue(all(x["choice"] is None for x in template["decisions"]))
        ready=deepcopy(template)
        for item in ready["decisions"]:
            item["choice"]="ABSTAIN"
        decisions=m.validate_responses(fake,ready)
        self.assertEqual(len(decisions),12)
        mutations=[
            lambda d:d["decisions"].pop(),
            lambda d:d["decisions"].reverse(),
            lambda d:d["decisions"][0].update(choice="UNKNOWN"),
            lambda d:d["decisions"][0].update(choice=None),
            lambda d:d.update(challenge_sha256="0"*64),
            lambda d:d.update(status="INDEPENDENT_EXPERT_GOLD"),
            lambda d:d["decisions"][0].update(extra="label"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=str(mutation)):
                wrong=deepcopy(ready)
                mutation(wrong)
                with self.assertRaises((DiagnosticError,ValueError,TypeError)):
                    m.validate_responses(fake,wrong)

    def test_known_controls_and_oracle_reversals(self):
        answers={}
        for i,project in enumerate(m.PROJECTS):
            row_a="B" if i%2 else "A"
            row_b="A" if i%2 else "B"
            answers[m.ident(project,"code-a")]=row_a
            answers[m.ident(project,"code-b")]=row_b
            answers[m.ident(project,"source-omitted")]="ABSTAIN"
        self.assertEqual(sum(x=="A" for x in answers.values()),4)
        perfect=m.score(answers,answers,origin="DISCLOSED_SYNTHETIC_BASELINE")
        self.assertEqual(perfect["matches_to_public_researcher_references"],12)
        self.assertEqual(perfect["complete_correct_parent_fix_reversals"],4)
        self.assertEqual(perfect["real_independent_human_expert_gold"],0)
        self.assertFalse(perfect["statistical_model_accuracy_claim"])
        blank={x:"ABSTAIN" for x in answers}
        no_source=m.score(answers,blank,origin="DISCLOSED_SYNTHETIC_BASELINE")
        self.assertEqual(no_source["matches_to_public_researcher_references"],4)
        self.assertEqual(no_source["complete_correct_parent_fix_reversals"],0)
        self.assertEqual(no_source["unnecessary_abstention_with_code_present"],8)
        static={m.ident(project,cond):("ABSTAIN" if cond=="source-omitted" else "A")
                for project in m.PROJECTS for cond in m.CONDITIONS}
        shortcut=m.score(answers,static,origin="DISCLOSED_SYNTHETIC_BASELINE")
        self.assertEqual(shortcut["matches_to_public_researcher_references"],8)
        self.assertEqual(shortcut["complete_correct_parent_fix_reversals"],0)
        invalid=m.score(answers,{x:"INVALID" for x in answers},
                        origin="DISCLOSED_SYNTHETIC_BASELINE")
        self.assertEqual(invalid["matches_to_public_researcher_references"],0)
        self.assertEqual(invalid["invalid_model_replies"],12)

    def test_no_revision_role_is_injected_in_rendered_prompt(self):
        text=m._render(self.protocol,
            "What does this code do?","if safe:\n    return X","One","Two")
        self.assertIn("if safe:",text)
        self.assertNotIn("{code}",text)
        self.assertIn("A. One",text)
        self.assertIn("B. Two",text)
        self.assertNotIn("parent code",text)
        self.assertNotIn("fixed code",text)
        self.assertNotIn("\\n",text)

    def test_model_reply_invalid_is_not_repaired_into_true_answer(self):
        expected={"A":"A","B":"B","ABSTAIN":"ABSTAIN",
                  "The answer is B":"INVALID",
                  "I don't know":"INVALID",
                  "ABSTAIN because":"INVALID"}
        for raw,normalized in expected.items():
            self.assertEqual(m.parse_choice(raw),normalized)

    def test_protocol_byte_mutation_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in (m.PROTOCOL,m.SOURCE_LOCK):
                dst=root/name
                dst.parent.mkdir(parents=True,exist_ok=True)
                dst.write_bytes((ROOT/name).read_bytes())
            lock=root/m.PROTOCOL
            lock.write_bytes(lock.read_bytes()+b"\n")
            with self.assertRaises(DiagnosticError):
                m.frozen(root)


if __name__=="__main__":
    unittest.main()
