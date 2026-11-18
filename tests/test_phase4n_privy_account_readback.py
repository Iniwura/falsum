"""Phase 4N: synthetic-only tests for comparing two distinct public wallets."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from falsum import phase4n_privy_account_readback as n
from falsum.phase4k_submission_readback import COMMENT_URL, INTENT, REPORTED_ROWS

PRIVY = "0x" + "a" * 40  # synthetic account, not the real contributor wallet
OLD = "0x" + "b" * 40  # synthetic historical public bounty wallet


def comment():
    return {
        "user": {"login": "Iniwura"},
        "body": (
            f"/submit\n\n**FALSUM — {INTENT} evaluation-material contribution**\n\n"
            f"**Contributor wallet:** `{OLD}`\n\n"
            f"I contributed **{REPORTED_ROWS} source-referenced evaluation preference pairs**.\n"
        ),
    }


def response_rows(states):
    return [
        {"intent_id": INTENT, "status": status, "row_hash": f"{i+1:064x}",
         "prompt": "SENSITIVE-PRIVATE-PROMPT", "chosen": "SENSITIVE-PRIVATE-ANSWER",
         "rejected": "SENSITIVE-PRIVATE-OTHER"}
        for i, status in enumerate(states)
    ]


def network(privy=None, old=None, *, offline_for=None, public_comment=None):
    pages = {PRIVY: response_rows(privy or []), OLD: response_rows(old or [])}
    urls = []
    def fetch(url, max_len):
        urls.append(url)
        if url == COMMENT_URL:
            return comment() if public_comment is None else public_comment
        q = parse_qs(urlsplit(url).query)
        address = q["submitter"][0]
        if address == offline_for:
            raise OSError("SENSITIVE-NETWORK-DETAIL")
        assert q["intent_id"] == [INTENT]
        assert address in pages, "unauthorized address being queried"
        rows = pages[address]
        start = int(q["offset"][0])
        size = int(q["limit"][0])
        return {"submitter": address, "count": len(rows), "rows": rows[start:start+size]}
    return fetch, urls


class PrivyContributorReadbackTests(unittest.TestCase):
    def test_both_distinct_wallets_are_queried_and_no_private_row_content_leaks(self):
        fetch, urls = network(privy=["eligible"] * 20, old=[])
        result = n.report(fetch, privy_address=PRIVY)
        self.assertTrue(result["addresses_distinct"])
        self.assertTrue(result["operator_association_is_based_on_user_provided_anjo_wallet_panel"])
        self.assertEqual(result["finding"],
                         "OPERATOR_SHOWN_PRIVY_ADDRESS_HAS_20_ELIGIBLE_ROWS_IN_PUBLIC_NODE")
        roles = result["accounts"]
        self.assertEqual(roles["signed_in_privy_wallet_user_observed"]["current_eligible_rows"], 20)
        self.assertEqual(roles["historical_bounty_comment_wallet"]["current_eligible_rows"], 0)
        self.assertTrue(all(x in [PRIVY, OLD] for x in
                            [parse_qs(urlsplit(u).query).get("submitter", [""])[0]
                             for u in urls if u != COMMENT_URL]))
        serial = json.dumps(result)
        for secret in [PRIVY, OLD, "SENSITIVE-PRIVATE-PROMPT",
                       "SENSITIVE-PRIVATE-ANSWER", "SENSITIVE-PRIVATE-OTHER",
                       "row_hash", "case_id", "private_row_body"]:
            self.assertNotIn(secret, serial)
        self.assertFalse(result["cryptographic_wallet_ownership_verified"])
        self.assertFalse(result["accepted_bounty_verified"])
        self.assertEqual(result["independent_appsec_gold_labels_verified"], 0)
        self.assertFalse(result["private_rows_persisted_or_logged"])

    def test_account_has_fewer_than_historical_reported_eligible(self):
        fetch, _ = network(privy=["eligible"] * 16 + ["admitted"] * 4, old=["eligible"])
        result = n.report(fetch, privy_address=PRIVY)
        self.assertIn("DIFFERS_FROM_HISTORICAL", result["finding"])
        privy = result["accounts"]["signed_in_privy_wallet_user_observed"]
        self.assertEqual(privy["current_eligible_rows"], 16)
        self.assertEqual(privy["current_total_rows"], 20)
        self.assertEqual(privy["counts_by_state"]["admitted"], 4)

    def test_privy_unavailable_retains_old_status_and_does_not_infer_zero(self):
        fetch, _ = network(old=[], offline_for=PRIVY)
        result = n.report(fetch, privy_address=PRIVY)
        self.assertEqual(result["finding"],
                         "OPERATOR_SHOWN_PRIVY_ADDRESS_LIVE_READBACK_UNAVAILABLE_UNKNOWN")
        self.assertIsNone(result["accounts"]["signed_in_privy_wallet_user_observed"]["current_eligible_rows"])
        self.assertEqual(result["accounts"]["historical_bounty_comment_wallet"]["current_eligible_rows"], 0)
        self.assertNotIn("SENSITIVE-NETWORK-DETAIL", json.dumps(result))

    def test_old_wallet_unavailable_cannot_be_reported_zero(self):
        fetch, _ = network(privy=["eligible"] * 20, offline_for=OLD)
        result = n.report(fetch, privy_address=PRIVY)
        self.assertIsNone(result["accounts"]["historical_bounty_comment_wallet"]["current_total_rows"])
        self.assertTrue(result["accounts"]["signed_in_privy_wallet_user_observed"]["readback_completed"])

    def test_bad_operator_address_or_same_as_old_wallet_rejected(self):
        fetch, _ = network()
        for wrong in (None, "not-an-address", "0x" + "g" * 40, OLD):
            with self.subTest(wrong=wrong), self.assertRaises(n.ContributorReadbackError):
                n.report(fetch, privy_address=wrong)

    def test_modified_or_wrong_author_submission_is_not_trusted(self):
        obj = comment()
        obj["user"]["login"] = "an-impostor"
        fetch, _ = network(public_comment=obj)
        with self.assertRaises(Exception):
            n.report(fetch, privy_address=PRIVY)

    def test_mutation_of_intent_fails_independently_on_both_wallets(self):
        fetch, _ = network(privy=["eligible"] * 20, old=["eligible"] * 3)
        def wrong(url, cap):
            obj = fetch(url, cap)
            if url != COMMENT_URL:
                obj["rows"] = [dict(row, intent_id="SOME_OTHER_INTENT") for row in obj["rows"]]
            return obj
        result = n.report(wrong, privy_address=PRIVY)
        for role in result["accounts"].values():
            self.assertIsNone(role["current_eligible_rows"])
            self.assertFalse(role["readback_completed"])

    def test_replayed_row_identity_fails_the_privy_check_not_cross_wallet(self):
        fetch, _ = network(privy=["eligible"] * 2, old=["eligible"])
        def duplicate(url, cap):
            obj = fetch(url, cap)
            if url != COMMENT_URL and parse_qs(urlsplit(url).query)["submitter"] == [PRIVY]:
                if len(obj["rows"]) > 1:
                    obj["rows"][1]["row_hash"] = obj["rows"][0]["row_hash"]
            return obj
        result = n.report(duplicate, privy_address=PRIVY)
        self.assertFalse(result["accounts"]["signed_in_privy_wallet_user_observed"]["readback_completed"])
        self.assertEqual(result["accounts"]["historical_bounty_comment_wallet"]["current_eligible_rows"], 1)

    def test_main_writes_private_safe_aggregate_only_and_rejects_overwrite(self):
        fetch, _ = network(privy=["eligible"] * 20, old=[])
        with tempfile.TemporaryDirectory() as workdir:
            out = Path(workdir) / "report.json"
            with patch.object(n, "report", return_value=n.report(fetch, privy_address=PRIVY)):
                self.assertEqual(n.main(["--out", str(out)]), 0)
            body = out.read_text()
            self.assertNotIn(PRIVY, body)
            self.assertNotIn(OLD, body)
            self.assertNotIn("SENSITIVE", body)
            self.assertIn("20", body)
            with self.assertRaises(SystemExit):
                n.main(["--out", str(out)])

    def test_unavailable_github_source_is_unknown_not_fabricated_zero(self):
        with tempfile.TemporaryDirectory() as workdir:
            out = Path(workdir) / "unknown.json"
            with patch.object(n, "report", side_effect=OSError("PRIVATE-DIAGNOSTIC-SECRET")):
                self.assertEqual(n.main(["--out", str(out)]), 0)
            d = json.loads(out.read_text())
            self.assertIsNone(d["accounts"])
            self.assertIn("UNAVAILABLE", d["finding"])
            self.assertNotIn("PRIVATE-DIAGNOSTIC-SECRET", out.read_text())


if __name__ == "__main__":
    unittest.main()
