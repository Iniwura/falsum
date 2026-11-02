"""No synthetic success can turn admitted into eligible or expose contributor data."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from falsum.phase3n_eligibility_guard import (
    ClaimError, reduce_mine, recorded_screenshot_milestone, write_private, STATUS
)


def sample(states=("admitted","admitted","admitted")):
    return {
        "submitter":"0x" + "a"*40,
        "count":len(states),
        "rows":[{
            "intent_id":"SECURITY_REVIEW_GENERAL",
            "row_hash":f"{i+1:064x}",
            "case_id":f"{i+101:064x}",
            "status":s,
            "provenance_class":"unverified",
            "reason_code":"near_duplicate" if s=="rejected" else None,
            "created_at":"2026-11-02T10:16:06Z"
        } for i,s in enumerate(states)]
    }


class SubmissionClaimBoundaries(unittest.TestCase):
    def test_admitted_20_is_not_eligible_20(self):
        d=reduce_mine(sample(("admitted",)*20),expect_rows=20)
        self.assertEqual(d["counts_by_state"]["admitted"],20)
        self.assertEqual(d["owned_eligible_rows_in_response"],0)
        self.assertFalse(d["eligible_network_evidence_present"])
        self.assertFalse(d["eligible_for_bounty_evaluation_part_claim"])
        self.assertFalse(d["all_rows_eligible"])
        self.assertFalse(d["bounty_submit_message_posted"])

    def test_actual_eligible_state_allows_preliminary_eligibility_statement(self):
        d=reduce_mine(sample(("eligible","admitted","rejected")),expect_rows=3)
        self.assertEqual(d["owned_eligible_rows_in_response"],1)
        self.assertTrue(d["eligible_network_evidence_present"])
        self.assertFalse(d["all_rows_eligible"])
        self.assertTrue(d["eligible_for_bounty_evaluation_part_claim"])
        self.assertFalse(d["bounty_maintainer_accepted"])
        self.assertEqual(d["reason_code_counts_only"],{"near_duplicate":1})

    def test_every_eligible_true_only_after_frozen_status(self):
        d=reduce_mine(sample(("eligible","eligible","eligible")))
        self.assertTrue(d["all_rows_eligible"])
        self.assertEqual(d["counts_by_state"]["admitted"],0)

    def test_unreviewed_screenshot_only_records_admission(self):
        d=recorded_screenshot_milestone()
        self.assertEqual(d["admitted_rows_visible"],20)
        self.assertEqual(d["duplicates_reported"],0)
        self.assertEqual(d["refused_reported"],0)
        self.assertEqual(d["eligible_rows_verified_by_this_screenshot"],0)
        self.assertFalse(d["network_owned_eligibility_queried"])
        self.assertTrue(d["screenshot_private_not_committed"])
        self.assertTrue(d["row_prompts_and_chosen_rejected_private"])
        self.assertNotIn("0x",json.dumps(d))

    def test_private_wallet_and_identifiers_are_not_in_aggregate(self):
        record=sample(("eligible","admitted"))
        result=reduce_mine(record)
        text=json.dumps(result)
        self.assertNotIn(record["submitter"],text)
        for item in record["rows"]:
            self.assertNotIn(item["row_hash"],text)
            self.assertNotIn(item["case_id"],text)
        self.assertFalse(result["wallet_or_row_hashes_in_output"])
        self.assertEqual(result["status"],STATUS)

    def test_no_wrong_intent_or_missing_wallet(self):
        bad=sample()
        bad["rows"][0]["intent_id"]="CODE_REVIEW_GENERAL"
        with self.assertRaises(ClaimError):reduce_mine(bad)
        bad=sample()
        bad["submitter"]="not a wallet"
        with self.assertRaises(ClaimError):reduce_mine(bad)

    def test_incomplete_pagination_or_unexpected_total_fails(self):
        bad=sample()
        bad["count"]=20
        with self.assertRaises(ClaimError):reduce_mine(bad)
        with self.assertRaises(ClaimError):reduce_mine(sample(),expect_rows=20)

    def test_duplicate_row_identity_rejected(self):
        bad=sample()
        bad["rows"][1]["row_hash"]=bad["rows"][0]["row_hash"]
        bad["rows"][1]["case_id"]=bad["rows"][0]["case_id"]
        with self.assertRaises(ClaimError):reduce_mine(bad)

    def test_unknown_network_state_cannot_auto_convert(self):
        bad=sample()
        bad["rows"][0]["status"]="accepted"
        with self.assertRaises(ClaimError):reduce_mine(bad)

    def test_invalid_row_hash_or_case_id_rejected(self):
        for key in ("row_hash","case_id"):
            with self.subTest(key=key):
                bad=sample()
                bad["rows"][0][key]="bad"
                with self.assertRaises(ClaimError):reduce_mine(bad)

    def test_reason_code_only_not_row_details(self):
        bad=sample(("rejected","rejected"))
        result=reduce_mine(bad)
        self.assertEqual(result["reason_code_counts_only"],{"near_duplicate":2})
        self.assertNotIn("created_at",result)
        bad["rows"][0]["reason_code"]="../../etc/passwd"
        with self.assertRaises(ClaimError):reduce_mine(bad)

    def test_outfile_mode_private_and_no_overwrite(self):
        report=reduce_mine(sample())
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/"status.json"
            write_private(out,report)
            self.assertEqual(json.loads(out.read_text()),report)
            with self.assertRaises(ClaimError):write_private(out,report)


if __name__=="__main__":
    unittest.main()
