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
    # Embed only the developer-authored public fixtures. No live Anjoman data.
    raw = json.dumps(report, separators=(",", ":"), ensure_ascii=False)
    raw = raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    head = html.escape(report["status"])
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>FALSUM — Evidence Lab</title><meta name="description" content="Executable synthetic security-review proof lab.">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<style>
:root{color-scheme:dark;--bg:#060a12;--p:#0c1320;--bd:#263348;--txt:#ebf3ff;--mut:#99a9c0;--blue:#548dff;--mint:#8af4d6;--red:#ff8e99;font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 72% -15%,#183b70 0,transparent 48%),var(--bg);color:var(--txt);min-height:100vh}
.container{max-width:1290px;margin:auto;padding:28px clamp(18px,4vw,50px) 80px}
nav{display:flex;align-items:center;justify-content:space-between;gap:20px;border-bottom:1px solid var(--bd);padding-bottom:25px}.nav-actions{display:flex;align-items:center;gap:16px}.nav-actions a{color:var(--mint);font-size:12px;text-decoration:none;font-weight:750}.nav-actions a:hover,.nav-actions a:focus-visible{text-decoration:underline}
.logo{font-size:19px;font-weight:850;letter-spacing:.18em}.logo i{font-style:normal;color:var(--blue)}
.tag{font-size:11px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;border:1px solid #39537c;color:#b4cffa;border-radius:50px;padding:8px 13px}
.hero{display:grid;grid-template-columns:1.4fr .6fr;gap:38px;align-items:end;margin:80px 0 48px}
.overline{color:var(--blue);font-size:12px;font-weight:800;letter-spacing:.2em;text-transform:uppercase}
h1{font-size:clamp(40px,6vw,82px);letter-spacing:-.065em;line-height:1.03;margin:16px 0 20px;max-width:830px}
h1 span{color:var(--blue)}.lead{color:#b0bed0;font-size:17px;max-width:660px;line-height:1.7}.hero-link{display:inline-block;margin-top:18px;padding:12px 17px;border:1px solid #507ac0;border-radius:10px;background:#162a47;text-decoration:none;color:#d8e8ff;font-size:13px;font-weight:750}.hero-link:hover,.hero-link:focus-visible{background:#203b63;outline:2px solid #628dcb;outline-offset:2px}
.note{padding:22px;border:1px solid #32435d;border-radius:18px;background:#0e1727;color:#c0d0e6;font-size:14px;line-height:1.7}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--bd);border:1px solid var(--bd);border-radius:20px;overflow:hidden;margin-bottom:48px}
.metric{padding:25px 22px;background:#0d1523}.metric strong{font-size:35px;display:block;letter-spacing:-.05em}.metric small{display:block;color:var(--mut);margin-top:5px;font-size:12px}
.section-heading{display:flex;align-items:center;gap:13px;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.15em;color:#b0c5df;margin-bottom:16px}
.section-heading:before{content:'';background:var(--blue);height:7px;width:7px;border-radius:50%}
.lab{display:grid;grid-template-columns:310px 1fr;gap:16px}
.nav-col{display:flex;flex-direction:column;gap:9px}.mission{border:1px solid var(--bd);background:#0a1220;color:var(--txt);text-align:left;border-radius:14px;padding:19px 19px;cursor:pointer;transition:border .15s ease,background .15s ease}
.mission:hover,.mission:focus-visible{border-color:var(--blue);outline:none}.mission[aria-pressed=true]{background:#122441;border-color:var(--blue)}.mission small{color:var(--blue);font-size:10px;font-weight:800;letter-spacing:.13em;display:block;margin-bottom:9px}.mission strong{font-size:15px;line-height:1.45}
.panel{border:1px solid var(--bd);border-radius:19px;background:linear-gradient(145deg,#0e192a,#090f1a);padding:clamp(21px,3.3vw,38px);min-height:510px}
.eyebrow{font-size:10px;color:#8fa9d2;font-weight:800;letter-spacing:.15em;text-transform:uppercase}
h2{font-size:clamp(25px,3vw,36px);letter-spacing:-.05em;margin:12px 0}.desc{font-size:15px;color:#aabbd1;line-height:1.65;max-width:650px}
.results{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin:30px 0 18px}
.result{border:1px solid #314056;border-radius:13px;padding:19px;background:#0b1422}.result.after{border-color:#2a695e;background:#09221f}
.label{font-size:10px;text-transform:uppercase;color:#a5bad7;letter-spacing:.16em;font-weight:750}.value{font-size:22px;letter-spacing:-.035em;margin-top:12px;font-weight:850}
.before .value{color:var(--red)}.after .value{color:var(--mint)}
.sub{font-size:12px;color:var(--mut);line-height:1.5;margin-top:12px}
.evidence{border-top:1px solid var(--bd);margin-top:26px;padding-top:24px}.fact{display:grid;grid-template-columns:145px 1fr;gap:12px;margin:12px 0;font-size:12px;line-height:1.65}.fact span:first-child{color:var(--mut);text-transform:uppercase;letter-spacing:.06em;font-size:10px;font-weight:700}
code{font:11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:#a8cffc;overflow-wrap:anywhere}
.footer{display:flex;flex-wrap:wrap;gap:20px;justify-content:space-between;margin-top:42px;padding-top:23px;border-top:1px solid var(--bd);font-size:12px;color:var(--mut)}
.status{color:var(--mint)}.fail{color:var(--red)}
@media(max-width:850px){.hero{grid-template-columns:1fr;margin:55px 0 35px}.lab{grid-template-columns:1fr}.nav-col{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}.metrics{grid-template-columns:repeat(2,1fr)}}
@media(max-width:560px){nav{align-items:flex-start;flex-wrap:wrap}.nav-actions{flex-wrap:wrap}.nav-col{grid-template-columns:1fr}.results{grid-template-columns:1fr}.fact{grid-template-columns:1fr;gap:2px}.hero{margin-top:46px}}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head>
<body><div class="container">
<nav><div class="logo">FALSUM<i>.</i></div><div class="nav-actions"><a href="https://github.com/Iniwura/falsum" rel="noopener noreferrer" target="_blank">GitHub + tests</a><div class="tag">Public synthetic evidence lab / 01</div></div></nav>
<section class="hero"><div><div class="overline">Security / Evaluators / Proof of behavior</div>
<h1>Security claims deserve a <span>cross-examination.</span></h1>
<p class="lead">Three fictional pull requests. Six real local Python executions. Each finding changes when the code is fixed, while legitimate behavior stays intact.</p><a class="hero-link" href="#lab">Explore measured results ↓</a>
</div><div class="note"><b>What this proves</b><p>Actual Python code ran against in-memory fixtures. This is a reproducible demonstration of evidence-aware security review, <b>not</b> a deployed product audit, trained AI scorer, or third-party integration.</p></div></section>
<div class="metrics"><div class="metric"><strong id="mission-count">3</strong><small>Synthetic mission workflows</small></div>
<div class="metric"><strong id="blocked">3/3</strong><small>Unwanted actions blocked after patch</small></div>
<div class="metric"><strong id="preserved">3/3</strong><small>Legitimate controls preserved</small></div>
<div class="metric"><strong id="unknown">3</strong><small>Unverified contexts kept unknown</small></div></div>
<div class="section-heading">01 / Inspection chamber — measured results</div>
<section class="lab" id="lab"><div class="nav-col" id="navitems" aria-label="Select a mission">
<button type="button" class="mission" aria-pressed="true" data-index="0"><small>EXCHANGE</small><strong>Withdrawal actor binding</strong></button>
<button type="button" class="mission" aria-pressed="false" data-index="1"><small>MODEL ECONOMY</small><strong>Callback authenticity</strong></button>
<button type="button" class="mission" aria-pressed="false" data-index="2"><small>WEB3 NATIVE & DEFI</small><strong>Relayer replay control</strong></button></div>
<div class="panel"><div class="eyebrow" id="mission-id">EXCHANGE / SYNTHETIC PR</div>
<h2 id="title">Withdrawals without actor binding</h2><p class="desc" id="description">A local historical before-and-after comparison.</p>
<div class="results"><div class="result before"><div class="label">Before patch / observed</div><div class="value" id="before-result">UNWANTED ACTION PASSED</div><div class="sub" id="before-state">From actual local test execution</div></div>
<div class="result after"><div class="label">After patch / observed</div><div class="value" id="after-result">UNWANTED ACTION BLOCKED</div><div class="sub" id="after-state">From actual local test execution</div></div></div>
<div class="evidence"><div class="section-heading">02 / Evidence ledger</div>
<div class="fact"><span>Safety question</span><strong id="question">Can a fictional endpoint accept an unauthorized operation?</strong></div>
<div class="fact"><span>Changed condition</span><span id="condition">A code-level permission boundary is missing.</span></div>
<div class="fact"><span>Legitimate control</span><span id="control">The intended caller still works.</span></div>
<div class="fact"><span>Unobserved context</span><span id="unknown-text">INSUFFICIENT EVIDENCE — never call it safe or compromised.</span></div>
<div class="fact"><span>Original function SHA-256</span><code id="hash-before">Local source hash</code></div>
<div class="fact"><span>Patched function SHA-256</span><code id="hash-after">Local source hash</code></div>
<div class="fact"><span>Scope / limitations</span><span id="scope">Synthetic program only</span></div></div>
</div></section><div class="footer"><span>FALSUM · SECURITY_REVIEW_GENERAL · PUBLIC SYNTHETIC FIXTURES · NOT A LIVE SCORER</span><span><a href="https://github.com/Iniwura/falsum/blob/main/docs/PHASE3Q.md" target="_blank" rel="noopener noreferrer" style="color:#a8cffc">How to reproduce + verify</a></span><span>Re-run: <code>PYTHONPATH=src python -m falsum.phase3q_mission_lab --out-dir /tmp/falsum-proof</code></span></div>
</div><script type="application/json" id="proof-data">""" + raw + """</script>
<script>
"use strict";
const report=JSON.parse(document.getElementById("proof-data").textContent);
const el=id=>document.getElementById(id);
el("mission-count").textContent=report.mission_workflow_category_count;
el("blocked").textContent=report.synthetic_unwanted_actions_blocked_after+"/3";
el("preserved").textContent=report.legitimate_controls_preserved_after+"/3";
el("unknown").textContent=report.missing_evidence_cases_marked_unknown;
function selectMission(i){
 const item=report.cases[i];
 if(!item)return;
 document.querySelectorAll(".mission").forEach((b,n)=>b.setAttribute("aria-pressed",String(n===i)));
 el("mission-id").textContent=item.mission+" / EXECUTABLE SYNTHETIC PR";
 el("title").textContent=item.title;
 el("description").textContent=item.summary;
 el("before-result").textContent=item.before.unsafe_action_accepted?"UNWANTED ACTION PASSED":"UNWANTED ACTION BLOCKED";
 el("after-result").textContent=item.after.unsafe_action_accepted?"UNWANTED ACTION PASSED":"UNWANTED ACTION BLOCKED";
 el("before-state").textContent=item.before.unsafe_state_name+" = "+item.before.unsafe_observed_state;
 el("after-state").textContent=item.after.unsafe_state_name+" = "+item.after.unsafe_observed_state;
 el("question").textContent=item.question;
 el("condition").textContent=item.unsafe_fact;
 el("control").textContent=item.control_fact+" Control passed both versions.";
 el("unknown-text").textContent=item.missing_evidence_review;
 el("hash-before").textContent=item.before_source_sha256;
 el("hash-after").textContent=item.after_source_sha256;
 el("scope").textContent=item.scope;
}
document.querySelectorAll(".mission").forEach(button=>button.addEventListener("click",()=>selectMission(Number(button.dataset.index))));
selectMission(0);
</script></body></html>
"""


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
