"""Phase 3L tests use synthetic-only rows; no actual evaluator questions leave operator storage."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from falsum.phase3l_evalpool_preflight import (
    CHAIN_ID, INTENT, STATUS, EvalpoolError, _normal, build,
    check_attestations, make_review_index, sign_message, validate_rows,
)


def row(n=0, *, source_kind="human"):
    if n == 0:
        prompt = "In this fictional test program, is an absent boundary check sufficient evidence of a demonstrated production exploit?"
        chosen = "A source warning alone is insufficient. Inspect the caller, relevant data flow, and actual execution conditions before reporting exploitation."
        rejected = "The missing check proves the production application was exploited. No relevant caller or runtime facts need verification before claiming damage."
    else:
        prompt = "For this separate fictional deployment, should a source patch be treated as proof that a third-party API disclosed a secret?"
        chosen = "A code fix identifies one potential risk, but real disclosure requires checking the affected version and a credential-bearing request path."
        rejected = "Any patched library is evidence of a leaked live customer credential. Additional endpoint, version and request evidence cannot matter."
    return {
        "intent_id": INTENT, "label_kind": "preference_pair",
        "prompt": prompt, "chosen": chosen, "rejected": rejected,
        "provenance": {"source_kind": source_kind,
                       "source_url": "https://github.com/example/public-demo/commit/1234567890abcdef"},
    }


def data(*items):
    return b"".join((json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for item in items)


def claims(data_bytes):
    _, hashes = validate_rows(data_bytes)
    return {
        "schema_version": 1, "intent_id": INTENT,
        "attestations": [{
            "row_sha256": h, "reviewer_id": f"example-human-reviewer-{i}",
            "source_and_patch_checked": True, "chosen_supported": True,
            "rejected_incorrect": True, "conflicts_resolved": True,
        } for i, h in enumerate(hashes)],
    }


class PrivateEvaluationPreflightTests(unittest.TestCase):
    def test_exact_two_synthetic_rows_formally_valid_but_not_eligible(self):
        raw = data(row(0), row(1))
        rows, hashes = validate_rows(raw)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(set(hashes)), 2)
        report = make_review_index(rows, hashes)
        self.assertEqual(report["intent_id"], INTENT)
        self.assertEqual(report["status"], STATUS)
        self.assertNotIn("prompt", json.dumps(report))
        self.assertNotIn("chosen", json.dumps(report))
        self.assertNotIn("rejected", json.dumps(report))

    def test_written_body_byte_for_byte_not_reformatted(self):
        raw = data(row(0), row(1))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path, reviews = root / "material.jsonl", root / "review.json"
            path.write_bytes(raw)
            reviews.write_text(json.dumps(claims(raw)))
            output = root / "private-handoff"
            result = build(path, reviews, output, "0x" + "a" * 40, "0123456789abcdef", CHAIN_ID)
            self.assertEqual((output / "PRIVATE-EVALPOOL-ROWS.jsonl").read_bytes(), raw)
            self.assertEqual(result["body_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result["row_count"], 2)
            self.assertFalse(result["signed"])
            self.assertFalse(result["uploaded"])
            self.assertEqual(result["network_eligible_rows"], 0)
            self.assertEqual(result["independent_expert_labels_verified"], 0)
            self.assertFalse(result["review_statement_check"]["reviewer_identity_authenticated"])
            self.assertFalse(result["review_statement_check"]["independent_expertise_verified"])

    def test_eip191_message_exact_five_lines_no_trailing_newline(self):
        raw = data(row())
        value = sign_message(raw, "abcdefgh01234567", 11155111)
        self.assertEqual(value, (
            "Telegraph eval-pool submission v1\n"
            "intent_id: SECURITY_REVIEW_GENERAL\n"
            "body_sha256: " + hashlib.sha256(raw).hexdigest() + "\n"
            "nonce: abcdefgh01234567\n"
            "chain_id: 11155111"
        ))
        self.assertEqual(len(value.splitlines()), 5)
        self.assertFalse(value.endswith("\n"))

    def test_wrong_intent_rejected(self):
        x = row(); x["intent_id"] = "CODE_REVIEW_GENERAL"
        with self.assertRaises(EvalpoolError):
            validate_rows(data(x))

    def test_generated_or_synthetic_source_kind_cannot_be_laundered(self):
        for kind in ("llm", "model", "synthetic", "generated"):
            with self.subTest(kind=kind):
                with self.assertRaises(EvalpoolError):
                    validate_rows(data(row(source_kind=kind)))

    def test_credential_or_nonpublic_url_rejected(self):
        urls = (
            "http://github.com/example/review", "https://localhost/patch",
            "https://127.0.0.1/test", "https://192.168.1.1/review",
            "https://169.254.169.254/latest", "https://user:pass@github.com/patch",
            "https://metadata.google.internal/anything",
        )
        for url in urls:
            with self.subTest(url=url):
                x=row();x["provenance"]["source_url"]=url
                with self.assertRaises(EvalpoolError):
                    validate_rows(data(x))

    def test_near_duplicate_and_same_prompt_refused(self):
        with self.assertRaises(EvalpoolError):
            validate_rows(data(row(), row()))
        x=row();y=row()
        y["prompt"]=x["prompt"]+" Clearly."
        y["rejected"]=row(1)["rejected"]
        with self.assertRaises(EvalpoolError):
            validate_rows(data(x,y))

    def test_reused_worse_answer_refused_even_when_prompts_differ(self):
        x,y=row(),row(1)
        y["rejected"]=x["rejected"]
        with self.assertRaises(EvalpoolError):
            validate_rows(data(x,y))

    def test_unbalanced_or_trivial_answer_refused(self):
        for change in ("short", "long"):
            with self.subTest(change=change):
                x=row()
                x["rejected"]="No check needed." if change=="short" else "Evidence is unnecessary. "*1000
                with self.assertRaises(EvalpoolError):
                    validate_rows(data(x))

    def test_secret_markers_blocked(self):
        for key, bad in (
            ("prompt","ghp_fake_token_for_test"),
            ("chosen","-----BEGIN PRIVATE KEY-----"),
            ("rejected","-----BEGIN OPENSSH PRIVATE KEY-----"),
        ):
            with self.subTest(key=key):
                x=row()
                x[key]=x[key]+bad
                with self.assertRaises(EvalpoolError):
                    validate_rows(data(x))

    def test_control_characters_and_missing_final_newline(self):
        raw=data(row())
        with self.assertRaises(EvalpoolError):
            validate_rows(raw[:-1])
        x=row()
        x["prompt"]+="\x00"
        with self.assertRaises(EvalpoolError):
            validate_rows(data(x))

    def test_wrong_row_fields_missing_fields_and_label_kind_rejected(self):
        for change in ("extra","no_prov","no_label","no_answer"):
            with self.subTest(case=change):
                x=row()
                if change=="extra":x["unexpected"]="spoof"
                if change=="no_prov":x.pop("provenance")
                if change=="no_label":x["label_kind"]="ground_truth"
                if change=="no_answer":x.pop("rejected")
                with self.assertRaises(EvalpoolError):
                    validate_rows(data(x))

    def test_row_size_and_body_limit(self):
        x=row()
        x["chosen"]="A valid answer with more words than a short reply. "*1800
        x["rejected"]="A different answer with a large number of words. "*1800
        with self.assertRaises(EvalpoolError):
            validate_rows(data(x))
        with self.assertRaises(EvalpoolError):
            validate_rows(b"x"*(32*1024*1024+1))

    def test_review_attestation_hash_binding_and_declared_checks(self):
        raw=data(row())
        _,hashes=validate_rows(raw)
        good=claims(raw)
        self.assertEqual(check_attestations(good,hashes)["submitted_review_statements"],1)
        for key,bad in (
            ("row_sha256","f"*64),("source_and_patch_checked",False),
            ("chosen_supported",False),("rejected_incorrect",False),
            ("conflicts_resolved",False),("reviewer_id",""),
        ):
            with self.subTest(key=key):
                x=copy.deepcopy(good)
                x["attestations"][0][key]=bad
                with self.assertRaises(EvalpoolError):
                    check_attestations(x,hashes)

    def test_review_claim_not_authenticated_or_independent(self):
        raw=data(row())
        _,hashes=validate_rows(raw)
        result=check_attestations(claims(raw),hashes)
        self.assertFalse(result["reviewer_identity_authenticated"])
        self.assertFalse(result["material_accuracy_certified"])
        self.assertFalse(result["independent_expertise_verified"])

    def test_empty_or_wrong_nonce_and_address_fails(self):
        for nonce in ("abc","A"*129, "invalid\nnonce"):
            with self.subTest(nonce=nonce), self.assertRaises(EvalpoolError):
                sign_message(data(row()),nonce,CHAIN_ID)
        for chain in (0, -1, True):
            with self.subTest(chain=chain), self.assertRaises(EvalpoolError):
                sign_message(data(row()),"validnonce",chain)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            inp=root/"data.jsonl";inp.write_bytes(data(row()))
            claim=root/"review.json";claim.write_text(json.dumps(claims(inp.read_bytes())))
            with self.assertRaises(EvalpoolError):
                build(inp,claim,root/"private","not-an-address","abcdef012345",CHAIN_ID)

    def test_refuse_overwriting_existing_private_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            inp=root/"data.jsonl";inp.write_bytes(data(row()))
            review=root/"review.json";review.write_text(json.dumps(claims(inp.read_bytes())))
            out=root/"private"
            build(inp,review,out,"0x"+"a"*40,"abcdef012345",CHAIN_ID)
            with self.assertRaises(EvalpoolError):
                build(inp,review,out,"0x"+"a"*40,"abcdef012346",CHAIN_ID)


if __name__ == "__main__":
    unittest.main()
