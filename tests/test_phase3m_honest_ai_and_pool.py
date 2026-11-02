"""Phase 3M: AI provenance honesty, private permissions, and public-status boundaries."""
from pathlib import Path
import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase3l_evalpool_preflight import (
    EvalpoolError, INTENT, validate_rows, build, sign_message,
)
from falsum.phase3m_public_pool_status import (
    PoolStatusError, interpret, ENDPOINT, load_live,
)


def row(kind="llm", tag="first"):
    return {
        "intent_id": INTENT,"label_kind":"preference_pair",
        "prompt": "For the completely fictional "+tag+" code deployment, is a source-level patch alone sufficient evidence of an actual customer data leak?",
        "chosen": "A patch shows a known weakness, but claiming a leak requires evidence of a reachable data flow and affected runtime. Verify the conditions before escalating.",
        "rejected": "The patch itself proves customer data was leaked, even without evidence of a reachable endpoint or the presence of any secret in that deployment.",
        "provenance":{"source_kind":kind,"source_url":"https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"}
    }


def body(*items):
    return b"".join((json.dumps(item,separators=(",",":"))+"\n").encode() for item in items)


def fake_status(eligible=2, submitters=3, minimum=5):
    return {
        "intent_id":INTENT,
        "by_state":{"quarantine":1,"admitted":2,"eligible":eligible,"rejected":1},
        "submitters":submitters,"eligible_submitters":min(submitters,eligible),
        "min_submitters":minimum,"current_epoch":32,
        "snapshot":{"corpus_version":"source-test","rows":eligible,"activation_epoch":32},
        "active_snapshot":None,
    }


class AIOriginHonesty(unittest.TestCase):
    def test_default_human_only_rejects_ai_draft(self):
        with self.assertRaises(EvalpoolError):validate_rows(body(row("llm")))

    def test_explicit_ai_optin_includes_all_documented_origin_classes(self):
        for kind in ("llm","model","generated","synthetic"):
            with self.subTest(kind=kind):
                rows,sha=validate_rows(body(row(kind)),allow_unverified_ai=True)
                self.assertEqual(len(rows),1)
                self.assertEqual(len(sha[0]),64)
                self.assertEqual(rows[0]["provenance"]["source_kind"],kind)

    def test_cannot_launder_mixed_human_ai_batch(self):
        other=row("human","another")
        other["rejected"]=other["rejected"]+" Another independent answer."
        with self.assertRaises(EvalpoolError):
            validate_rows(body(row("llm"),other),allow_unverified_ai=True)

    def test_honest_unsigned_private_handoff_without_invented_reviewer(self):
        raw=body(row("llm"))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            src=root/"private.jsonl";src.write_bytes(raw)
            report=build(src,None,root/"output","0x"+"a"*40,"abcdef12345678",11155111,allow_unverified_ai=True)
            self.assertEqual(report["origin_declarations"],["llm"])
            self.assertEqual(report["provenance_class"],"unverified")
            self.assertEqual(report["review_statement_check"]["submitted_review_statements"],0)
            self.assertFalse(report["review_statement_check"]["independent_expertise_verified"])
            self.assertFalse(report["signed"])
            self.assertFalse(report["uploaded"])
            self.assertFalse(report["network_eligibility_checked"])
            self.assertEqual(report["network_eligible_rows"],0)
            self.assertEqual((root/"output/PRIVATE-EVALPOOL-ROWS.jsonl").read_bytes(),raw)
            self.assertEqual((root/"output/EIP191-MESSAGE-TO-SIGN.txt").read_text(),
                             sign_message(raw,"abcdef12345678",11155111))
            if os.name=="posix":
                self.assertEqual(stat.S_IMODE((root/"output").stat().st_mode),0o700)
                self.assertEqual(stat.S_IMODE((root/"output/PRIVATE-EVALPOOL-ROWS.jsonl").stat().st_mode),0o600)

    def test_ai_draft_cannot_invent_review_attestations(self):
        raw=body(row("llm"))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);inp=root/"rows.jsonl";inp.write_bytes(raw)
            review=root/"fake_review.json";review.write_text("{}")
            with self.assertRaises(EvalpoolError):
                build(inp,review,root/"out","0x"+"a"*40,"abcdefgh01234567",11155111,allow_unverified_ai=True)

    def test_human_mode_still_requires_genuine_review_claim_file(self):
        raw=body(row("human"))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);inp=root/"rows.jsonl";inp.write_bytes(raw)
            with self.assertRaises(EvalpoolError):
                build(inp,None,root/"out","0x"+"a"*40,"abcdefgh01234567",11155111)

    def test_unverified_class_rejects_forced_human_origin_when_opted_out(self):
        with self.assertRaises(EvalpoolError):
            validate_rows(body(row("other")))


class LivePublicPoolSafety(unittest.TestCase):
    def test_public_counts_never_claim_falsum_user_ownership(self):
        status=interpret(fake_status())
        self.assertEqual(status["public_eligible_rows_in_intent"],2)
        self.assertFalse(status["pool_contributor_threshold_reached"])
        self.assertFalse(status["own_submission_checked"])
        self.assertEqual(status["falsum_owned_eligible_rows_confirmed"],0)
        self.assertTrue(status["operator_address_was_not_provided"])

    def test_positive_threshold_still_not_user_claim(self):
        status=interpret(fake_status(eligible=9,submitters=7))
        self.assertTrue(status["pool_contributor_threshold_reached"])
        self.assertEqual(status["falsum_owned_eligible_rows_confirmed"],0)

    def test_invalid_source_states_rejected(self):
        d=fake_status();d["by_state"]["eligible"]=True
        with self.assertRaises(PoolStatusError):interpret(d)
        d=fake_status();d["by_state"]["winners"]=9
        with self.assertRaises(PoolStatusError):interpret(d)

    def test_wrong_intent_and_impossible_contributor_counts_rejected(self):
        d=fake_status();d["intent_id"]="CHAT_COMPLETION_GENERAL"
        with self.assertRaises(PoolStatusError):interpret(d)
        d=fake_status();d["eligible_submitters"]=12
        with self.assertRaises(PoolStatusError):interpret(d)

    def test_missing_snapshot_optional_when_not_yet_frozen(self):
        d=fake_status();d["snapshot"]=None
        value=interpret(d)
        self.assertFalse(value["active_snapshot_present"])
        self.assertFalse(value["snapshot_pending_activation"])

    def test_non_200_and_mismatched_redirect_cannot_be_treated_as_public_counts(self):
        class FakeResponse:
            def __enter__(self):return self
            def __exit__(self,*args):return None
            status=200
            def geturl(self):return "https://untrusted.example.org/data"
            def read(self,n):return json.dumps(fake_status()).encode()
        with patch("falsum.phase3m_public_pool_status.urllib.request.urlopen",return_value=FakeResponse()):
            with self.assertRaises(PoolStatusError):load_live()

    def test_public_endpoint_is_fixed_known_intent_without_contributor_data(self):
        self.assertEqual(ENDPOINT,"https://devnode.telegraphprotocol.com/api/evalpool/status?intent_id=SECURITY_REVIEW_GENERAL")
        self.assertNotIn("submitter=",ENDPOINT)
        self.assertNotIn("signature",ENDPOINT)


if __name__=="__main__":
    unittest.main()
