"""Phase 3Q: genuinely executable, no-network *synthetic* PR security-review lab.

Three independent software workflows inspired by H2 mission categories, with
BEFORE/AFTER Python implementations and executable counterfactual controls.

The test executes real code, but the application, identities, currency balances
and events are local *fictional fixtures*. It does NOT run an AI scoring adapter,
prove a real project vulnerable, verify mission adoption or certify hidden rows.
No third-party application and no live account is touched.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import html
import inspect
import json
from pathlib import Path

STATUS = "PHASE3Q_EXECUTABLE_PUBLIC_SYNTHETIC_MISSION_PROOF_NOT_REAL_APP"
INTENT = "SECURITY_REVIEW_GENERAL"


class MissionProofError(ValueError):
    pass


# Exchange / payment-service PR: the before version trusts the owner parameter
# without comparing it to the authenticated actor supplied by the gateway.
def exchange_before(ledger: dict, actor: str, owner: str, amount: int) -> bool:
    if type(amount) is not int or amount <= 0 or ledger.get(owner, 0) < amount:
        return False
    ledger[owner] -= amount
    return True


def exchange_after(ledger: dict, actor: str, owner: str, amount: int) -> bool:
    if actor != owner:
        return False
    if type(amount) is not int or amount <= 0 or ledger.get(owner, 0) < amount:
        return False
    ledger[owner] -= amount
    return True


# Model Economy / agent callback PR: validate a signature BEFORE consuming
# the payload. All bytes, including the secret, are synthetic and in-memory.
def callback_before(body: bytes, signature: str, secret: bytes) -> bool:
    data = json.loads(body)
    return data.get("event") == "job.completed"


def callback_after(body: bytes, signature: str, secret: bytes) -> bool:
    actual = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, actual):
        return False
    data = json.loads(body)
    return data.get("event") == "job.completed"


# Web3 / DeFi off-chain relayer PR: reject an already-processed event_id
# *before* updating a fictional credit ledger.
def relay_before(ledger: dict, seen: set, event_id: str, amount: int) -> bool:
    if type(amount) is not int or amount <= 0:
        return False
    ledger["synthetic-account"] = ledger.get("synthetic-account", 0) + amount
    seen.add(event_id)
    return True


def relay_after(ledger: dict, seen: set, event_id: str, amount: int) -> bool:
    if event_id in seen or type(amount) is not int or amount <= 0:
        return False
    ledger["synthetic-account"] = ledger.get("synthetic-account", 0) + amount
    seen.add(event_id)
    return True


MISSION_META = (
    {
        "id": "exchange-owner-binding",
        "mission": "EXCHANGE",
        "title": "Withdrawals without actor binding",
        "summary": "A caller-controlled owner field bypasses the authenticated actor.",
        "unsafe_fact": "Authenticated actor and requested balance owner differ.",
        "control_fact": "Authenticated actor and requested balance owner match.",
        "evidence_question": "Can actor B withdraw synthetic funds from owner A's account?",
        "scope": "In-memory integer balances; actor identity is supplied as a trusted fixture. No actual identity provider or funds.",
        "before": exchange_before,
        "after": exchange_after,
    },
    {
        "id": "model-agent-callback-integrity",
        "mission": "MODEL ECONOMY",
        "title": "Completion webhook without authenticity",
        "summary": "A callback accepts an unauthenticated completion event.",
        "unsafe_fact": "A synthetic callback signature is invalid for the exact body.",
        "control_fact": "Callback signature matches the body using the test secret.",
        "evidence_question": "Can a forged completion callback pass the local handler?",
        "scope": "In-memory synthetic HMAC bytes. No deployed agents, live secrets, web requests or real vendor endpoints.",
        "before": callback_before,
        "after": callback_after,
    },
    {
        "id": "web3-relayer-replay",
        "mission": "WEB3 NATIVE & DEFI",
        "title": "Relayer credit without replay protection",
        "summary": "A previously processed event can credit a fictional ledger twice.",
        "unsafe_fact": "The same synthetic event identifier is delivered a second time.",
        "control_fact": "Two distinct synthetic event identifiers arrive once each.",
        "evidence_question": "Does replaying an already processed relay event double-credit the account?",
        "scope": "Single-process synthetic event IDs and a fictional ledger. No blockchain, signatures, concurrent writes or real assets.",
        "before": relay_before,
        "after": relay_after,
    },
)


def _sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _source_sha(func) -> str:
    return _sha(inspect.getsource(func).encode("utf-8"))


def _exchange(func) -> dict:
    unauthorized = {"victim": 100}
    wrong_actor_approved = func(unauthorized, "outsider", "victim", 20)
    remaining_after_wrong_actor = unauthorized["victim"]
    owner = {"victim": 100}
    owner_approved = func(owner, "victim", "victim", 20)
    return {
        "unsafe_action_accepted": wrong_actor_approved,
        "unsafe_observed_state": remaining_after_wrong_actor,
        "control_action_accepted": owner_approved,
        "control_observed_state": owner["victim"],
        "unsafe_state_name": "victim_balance_after_wrong_actor",
        "control_state_name": "victim_balance_after_right_actor",
        "unsafe_expected_before": 80,
        "unsafe_expected_after": 100,
        "control_expected": 80,
    }


def _callback(func) -> dict:
    secret = b"synthetic-demo-key-not-real"
    body = b'{"event":"job.completed","id":"fictional-job-17"}'
    correct_signature = hmac.new(secret, body, hashlib.sha256).hexdigest()
    wrong_signature = "0" * 64
    return {
        "unsafe_action_accepted": func(body, wrong_signature, secret),
        "unsafe_observed_state": "accepted_without_valid_signature" if func(body, wrong_signature, secret) else "rejected_invalid_signature",
        "control_action_accepted": func(body, correct_signature, secret),
        "control_observed_state": "accepted_valid_signature" if func(body, correct_signature, secret) else "rejected_valid_signature",
        "unsafe_state_name": "invalid_signature_handling",
        "control_state_name": "valid_signature_handling",
        "unsafe_expected_before": "accepted_without_valid_signature",
        "unsafe_expected_after": "rejected_invalid_signature",
        "control_expected": "accepted_valid_signature",
    }


def _relay(func) -> dict:
    replay_ledger, replay_seen = {}, set()
    first_ok = func(replay_ledger, replay_seen, "fictional-event-1", 12)
    replay_ok = func(replay_ledger, replay_seen, "fictional-event-1", 12)
    distinct_ledger, distinct_seen = {}, set()
    c1 = func(distinct_ledger, distinct_seen, "fictional-event-1", 12)
    c2 = func(distinct_ledger, distinct_seen, "fictional-event-2", 12)
    return {
        "unsafe_action_accepted": replay_ok,
        "unsafe_observed_state": replay_ledger.get("synthetic-account", 0),
        "control_action_accepted": c1 and c2,
        "control_observed_state": distinct_ledger.get("synthetic-account", 0),
        "unsafe_state_name": "credits_after_duplicate_event",
        "control_state_name": "credits_after_two_distinct_events",
        "unsafe_expected_before": 24,
        "unsafe_expected_after": 12,
        "control_expected": 24,
        "first_event_accepted": first_ok,
    }


RUNNERS = {"exchange-owner-binding": _exchange, "model-agent-callback-integrity": _callback, "web3-relayer-replay": _relay}


def _expected(mission_id: str, before: dict, after: dict) -> None:
    for name, result, vulnerable in (("before", before, True), ("after", after, False)):
        if (result["unsafe_action_accepted"] is not vulnerable or
            result["unsafe_observed_state"] != result["unsafe_expected_" + name] or
            result["control_action_accepted"] is not True or
            result["control_observed_state"] != result["control_expected"]):
            raise MissionProofError(f"{mission_id}: unexpected genuine {name} behavior; report cannot claim proof")
        if mission_id == "web3-relayer-replay" and result.get("first_event_accepted") is not True:
            raise MissionProofError("relayer first event was not accepted")
    if before["unsafe_observed_state"] == after["unsafe_observed_state"]:
        raise MissionProofError("before and after application state did not actually diverge")


def capture() -> dict:
    cases = []
    for m in MISSION_META:
        before, after = RUNNERS[m["id"]](m["before"]), RUNNERS[m["id"]](m["after"])
        _expected(m["id"], before, after)
        identity = m["id"]
        cases.append({
            "id": identity, "mission": m["mission"], "title": m["title"],
            "summary": m["summary"], "question": m["evidence_question"], "scope": m["scope"],
            "unsafe_fact": m["unsafe_fact"], "control_fact": m["control_fact"],
            "before_source_sha256": _source_sha(m["before"]),
            "after_source_sha256": _source_sha(m["after"]),
            "before_code": inspect.getsource(m["before"]),
            "after_code": inspect.getsource(m["after"]),
            "before": before, "after": after,
            "real_python_fixture_executed": True,
            "independent_external_application_tested": False,
            "before_provisional_review": "Local fixture reproduced unwanted behavior; review the code boundary.",
            "after_provisional_review": "Local fixture blocked unwanted behavior and preserved its legitimate control.",
            "missing_evidence_review": "INSUFFICIENT_EVIDENCE — no code or runtime was supplied; cannot infer risk or safety.",
            "human_certified_security_assessment": False,
        })
    return {
        "schema_version": 1, "status": STATUS, "intent": INTENT,
        "demo_source": "public synthetic Python PR fixtures executed by a Python interpreter",
        "mission_workflow_categories": [r["mission"] for r in cases],
        "mission_workflow_category_count": 3,
        "synthetic_before_after_executions": 6,
        "synthetic_unwanted_actions_observed_before": sum(c["before"]["unsafe_action_accepted"] for c in cases),
        "synthetic_unwanted_actions_blocked_after": sum(not c["after"]["unsafe_action_accepted"] for c in cases),
        "legitimate_controls_preserved_after": sum(c["after"]["control_action_accepted"] for c in cases),
        "missing_evidence_cases_marked_unknown": 3,
        "actual_third_party_mission_apps_verified": 0,
        "real_assets_or_credentials_used": False,
        "actual_evaluator_model_scoring_executed": False,
        "independent_expert_security_labels": 0,
        "network_private_cases_used": False,
        "network_eligible_rows_created_by_this_lab": 0,
        "evaluator_model_registered": False,
        "mission_adoption_verified": False,
        "notice": "This is a real interpreter execution against three *fictional* before/after PR implementations. Observed behavior is true only for these synthetic cases. The report is NOT AI-model accuracy, third-party mission integration, production exploitability or independent security certification.",
        "cases": cases,
    }


def _page(report: dict) -> str:
    """Render a genuine evidence-driven, Firma-inspired editorial case-study site.

    The source snippets and result states are captured from actual local Python
    code, while the static browser only compares and visualizes those outputs.
    The template is local and intentionally contains no remote resources.
    """
    template_path = (
        Path(__file__).resolve().parent
        / "templates"
        / "firma_editorial_evidence_lab.html"
    )
    template = template_path.read_text(encoding="utf-8")
    placeholder = "__FALSUM_DATA__"
    if template.count(placeholder) != 1:
        raise MissionProofError("exactly one safe data-placeholder is required")
    raw = json.dumps(report, separators=(",", ":"), ensure_ascii=False)
    # No captured source text can terminate the inert JSON script or inject HTML.
    for char, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e")):
        raw = raw.replace(char, escaped)
    return template.replace(placeholder, raw)


def write_outputs(out_dir: Path, report: dict) -> None:
    if out_dir.exists() or out_dir.is_symlink():
        raise MissionProofError("output directory must be new, do not overwrite prior evidence")
    out_dir.mkdir(parents=True)
    (out_dir / "ACTUAL-SYNTHETIC-RUNTIME-PROOF.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "index.html").write_text(_page(report), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run real Python synthetic mission PR code and export interactive evidence lab")
    p.add_argument("--out-dir", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        r = capture()
        write_outputs(a.out_dir, r)
        print(json.dumps({
            "status": r["status"], "actual_python_before_after_executions": r["synthetic_before_after_executions"],
            "unwanted_actions_blocked_after": r["synthetic_unwanted_actions_blocked_after"],
            "legitimate_controls_preserved": r["legitimate_controls_preserved_after"],
            "third_party_applications_verified": 0, "trained_evaluator_scoring": False,
            "proof": str(a.out_dir / "ACTUAL-SYNTHETIC-RUNTIME-PROOF.json"),
            "interactive_demo": str(a.out_dir / "index.html"),
        }, indent=2))
        return 0
    except (MissionProofError, OSError, ValueError, TypeError) as exc:
        p.exit(1, f"FALSUM PHASE 3Q EVIDENCE LAB FAILED: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
