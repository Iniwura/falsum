"""AI-authored, real-source contrastive AppSec tasks, strictly research-only.

Public packet: real pre-fix source + stated hypothetical deployment + two
equally plausible competing answers, WITHOUT proposed preference or advisory.
Private audit: source provenance, proposed answer, AI caveats. The private
packet is not expert judgement, actual exploit evidence, or sealed holdout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Callable

from .pre_fix_challenges import ChallengeError, build_challenges, _canonical
from .real_fix_replay import ReplayError
from .real_fix_corpus import RealFixError, load_queue
from .model_eval import render

STATUS = "AI_ASSISTED_DRAFT_COMPARISONS_NOT_INDEPENDENTLY_VALIDATED"
SPEC_STATUS = "AI_AUTHORED_SECURITY_REVIEW_DRAFT_UNREVIEWED"
PRIVATE_STATUS = "AI_PROPOSED_ANSWER_KEY_NOT_APPROVED"
CASE_KEYS = {"id", "source_review", "finding_answer", "conditional_answer", "scenarios"}
REVIEW_KEYS = {"code_boundary", "fix_review", "regression_evidence", "limitations"}
SCENARIO_KEYS = {"id", "proposed_preferred", "facts"}
ALLOWED_KINDS = ("finding", "conditional")
INTENT = "SECURITY_REVIEW_GENERAL"
ADVISORY_ID = re.compile(r"(?i)\b(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,})\b")


class AIReviewError(ValueError):
    """Refuse short, repetitive, forged, or incorrectly promoted synthetic labels."""


def _sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _require_str(value: object, name: str, low: int = 20, high: int = 1200) -> str:
    if not isinstance(value, str) or not low <= len(value.strip()) <= high:
        raise AIReviewError(f"{name} requires {low}..{high} characters")
    return value.strip()


def validate_specs(specs: dict, queue: dict) -> list[dict]:
    if (not isinstance(specs, dict)
            or set(specs) != {"schema_version", "status", "intent", "research_only",
                              "independent_human_reviews", "model_training_authorized",
                              "network_eligible", "notice", "cases"}
            or specs["schema_version"] != 1 or specs["status"] != SPEC_STATUS
            or specs["intent"] != INTENT or specs["research_only"] is not True
            or type(specs["independent_human_reviews"]) is not int
            or specs["independent_human_reviews"] != 0
            or specs["model_training_authorized"] is not False
            or specs["network_eligible"] is not False):
        raise AIReviewError("untrusted source specs or attempted label promotion")
    _require_str(specs["notice"], "research-only caveat", 100, 1000)
    rows = specs["cases"]
    sources = queue["cases"]
    if not isinstance(rows, list) or len(rows) != len(sources) or len(rows) < 4:
        raise AIReviewError("AI drafts must cover each source-verified project exactly once")
    if [row.get("id") for row in rows if isinstance(row, dict)] != [x["id"] for x in sources]:
        raise AIReviewError("AI drafts must follow source-queue ordering and IDs")
    answers_seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != CASE_KEYS:
            raise AIReviewError("unrecognized or missing AI review case fields")
        notes = row["source_review"]
        if not isinstance(notes, dict) or set(notes) != REVIEW_KEYS:
            raise AIReviewError("missing fact-versus-uncertainty review fields")
        for field in REVIEW_KEYS:
            _require_str(notes[field], f'{row["id"]}.{field}', 80, 1000)
        for label in ALLOWED_KINDS:
            answer = _require_str(row[f"{label}_answer"], f'{row["id"]}.{label}', 220, 1200)
            words = len(answer.split())
            if not 40 <= words <= 115:
                raise AIReviewError("AI candidate answer outside bounded 40..115 word count")
            if answer.casefold() in answers_seen:
                raise AIReviewError("identical or reused AI answer makes quality shortcut")
            answers_seen.add(answer.casefold())
            if ADVISORY_ID.search(answer):
                raise AIReviewError("no advisory ID directly inside candidate answers")
        finding = row["finding_answer"]
        cautious = row["conditional_answer"]
        ratio = len(finding.split()) / len(cautious.split())
        if not 0.75 <= ratio <= 1.34:
            raise AIReviewError(f'{row["id"]}: answer-length shortcut {ratio:.3f}')
        scenarios = row["scenarios"]
        if (not isinstance(scenarios, list) or len(scenarios) != 2
                or [s.get("id") for s in scenarios if isinstance(s, dict)]
                != ["exposure", "missing-precondition"]):
            raise AIReviewError("each family must have exposure then absent-precondition scenario")
        if [s.get("proposed_preferred") for s in scenarios] != ["finding", "conditional"]:
            raise AIReviewError("opposite research-answer preference required for same candidates")
        seen_facts = set()
        for scenario in scenarios:
            if not isinstance(scenario, dict) or set(scenario) != SCENARIO_KEYS:
                raise AIReviewError("scenario includes unrecognized fields")
            facts = _require_str(scenario["facts"], "deployment facts", 155, 850)
            if ADVISORY_ID.search(facts) or "github.com" in facts.casefold():
                raise AIReviewError("no public fix or advisory identity inside question")
            if facts.casefold() in seen_facts:
                raise AIReviewError("identical deployment contexts")
            seen_facts.add(facts.casefold())
    return rows


def build(specs: dict, queue: dict, evidence: dict,
          reader: Callable[[str], bytes] | None = None) -> tuple[dict, dict]:
    rows = validate_specs(specs, queue)
    if (evidence.get("status") != "SOURCE_VERIFIED_LABELS_UNREVIEWED"
            or evidence.get("source_verified") != len(rows)
            or evidence.get("independent_human_reviews") != 0
            or evidence.get("training_authorized") is not False
            or evidence.get("network_eligible") is not False
            or [case["id"] for case in evidence.get("cases", [])] != [r["id"] for r in rows]):
        raise AIReviewError("verified source report inconsistent with the quarantine queue")
    # This re-fetches actual parent + fixed source AND test bytes, checks git
    # blob identities and requires exact pre/post patch replay, not merely links.
    prompts, citations = build_challenges(evidence, reader)
    prompt_map = {p["challenge_id"]: p["prompt"] for p in prompts["prompts"]}
    per_case = {}
    for ref in citations["records"]:
        if ref["challenge_id"] not in prompt_map:
            raise AIReviewError("missing real-source prompt digest")
        per_case.setdefault(ref["case_id"], []).append(ref)
    public_cases, key_cases = [], []
    for row, source in zip(rows, queue["cases"]):
        choices = per_case.get(row["id"])
        if not choices:
            raise AIReviewError("no actual source-code excerpt for requested project")
        # Select the largest changed-code window, tie-break by last hunk.
        # Jinja's import hunk is not a meaningful sandbox-review excerpt.
        ref = max(enumerate(choices),
                  key=lambda pair: (pair[1]["source_lines"][1] -
                                    pair[1]["source_lines"][0], pair[0]))[1]
        code_question = prompt_map[ref["challenge_id"]]
        for scenario in row["scenarios"]:
            case_id = f'{row["id"]}:{scenario["id"]}'
            question = (
                code_question
                + "\n\nDeployment evidence (hypothetical research scenario):\n"
                + scenario["facts"]
                + "\n\nAssess only this deployment's supported finding or missing preconditions."
            )
            if len(question.encode("utf-8")) > 5000:
                raise AIReviewError("task exceeds bounded size; never truncate security evidence")
            finding = row["finding_answer"]
            conditional = row["conditional_answer"]
            finding_is_a = bool(hashlib.sha256(case_id.encode("utf-8")).digest()[0] & 1)
            a, b = (finding, conditional) if finding_is_a else (conditional, finding)
            preferred = ("A" if finding_is_a else "B") if scenario["proposed_preferred"] == "finding" else (
                "B" if finding_is_a else "A")
            public_cases.append({
                "case_id": case_id,
                "question": question,
                "candidate_a": a,
                "candidate_b": b,
            })
            key_cases.append({
                "case_id": case_id,
                "source_case": source["id"],
                "source_repository": source["repository"],
                "source_commit": source["commit"], "parent_commit": source["parent"],
                "source_path": source["source_path"], "source_lines": ref["source_lines"],
                "test_path": source["test_path"],
                "advisory_url": source["public_source"],
                "review_notes": row["source_review"],
                "proposed_preferred": preferred,
                "proposed_kind": scenario["proposed_preferred"],
                "research_provenance": "AI_AUTHORED_HYPOTHETICAL_CONTEXT_NOT_HUMAN_REVIEWED",
                "human_validated": False, "eligible": False,
            })
    if len(public_cases) != 2 * len(rows) or len({x["case_id"] for x in public_cases}) != len(public_cases):
        raise AIReviewError("missing or duplicate contrastive project/context cases")
    # Family-pair answer text MUST be identical, with opposite preferred kinds.
    for i in range(0, len(public_cases), 2):
        a, b = public_cases[i:i+2]
        if {a["candidate_a"], a["candidate_b"]} != {b["candidate_a"], b["candidate_b"]}:
            raise AIReviewError("contrastive pair has candidate wording leakage")
        x, y = key_cases[i:i+2]
        selected = lambda p, k: p["candidate_a"] if k["proposed_preferred"] == "A" else p["candidate_b"]
        if selected(a, x) == selected(b, y):
            raise AIReviewError("context reversal does not change correct research-preferred answer")
    public = {
        "schema_version": 1, "status": STATUS, "intent": INTENT,
        "human_reviews": 0, "model_training_authorized": False,
        "network_eligible": False, "research_only": True, "sealed_holdout": False,
        "cases": public_cases,
        "notice": "Eight AI-authored hypothetical, provisional A/B comparisons; real parent code but NOT human-reviewed preference labels, holdout, network-eligible rows or final model quality.",
    }
    private = {
        "schema_version": 1, "status": PRIVATE_STATUS,
        "source_cases_sha256": evidence["cases_sha256"],
        "source_queue_sha256": _sha(_canonical(queue)),
        "ai_specs_sha256": _sha(_canonical(specs)),
        "public_packet_sha256": _sha(_canonical(public)),
        "human_reviews": 0, "model_training_authorized": False,
        "network_eligible": False, "entries": key_cases,
        "notice": "A model-generated provisional answer key is not an independent security judgment; never use as sealed holdout, eligibility attestation or model release gate.",
    }
    return public, private


def token_audit(public: dict, tokenize: Callable[[str], list[int]]) -> dict:
    if (not isinstance(public, dict) or public.get("status") != STATUS
            or public.get("model_training_authorized") is not False
            or public.get("network_eligible") is not False
            or public.get("human_reviews") != 0 or public.get("sealed_holdout") is not False):
        raise AIReviewError("only the quarantined AI benchmark can be token-audited")
    cases = public.get("cases")
    if not isinstance(cases, list) or len(cases) != 8:
        raise AIReviewError("eight public contrastive cases required")
    records = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"case_id", "question", "candidate_a", "candidate_b"}:
            raise AIReviewError("unexpected label metadata in public question")
        n=[]
        for value in ("candidate_a", "candidate_b"):
            token_ids = tokenize(render(case["question"], case[value]))
            if not isinstance(token_ids, list) or not token_ids or any(type(t) is not int or t < 0 for t in token_ids):
                raise AIReviewError("tokenizer returned invalid or empty token IDs")
            n.append(len(token_ids))
        records.append({"case_id": case["case_id"], "a_full_tokens": n[0],
                        "b_full_tokens": n[1], "within_512": max(n) <= 512})
    failures = [r["case_id"] for r in records if not r["within_512"]]
    return {"schema_version": 1, "status": "AI_DRAFT_FULL_MODEL_INPUT_TOKEN_AUDIT_NOT_ACCURACY",
            "checked_pairs": len(records), "model_inputs_checked": len(records)*2,
            "maximum_full_model_tokens": max(max(r["a_full_tokens"], r["b_full_tokens"]) for r in records),
            "token_cap": 512, "all_pass": not failures, "failures": failures,
            "records": records, "human_reviews": 0, "network_eligible": False,
            "model_accuracy_measured": False}


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description="Build and tokenize AI-assisted draft review pairs from EXACT real upstream source")
    p.add_argument("--specs", type=Path, default=Path("data/ai-review-drafts.json"))
    p.add_argument("--queue", type=Path, default=Path("data/real-fix-queue.json"))
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--questions-out", type=Path, required=True)
    p.add_argument("--key-out", type=Path, required=True)
    p.add_argument("--token-out", type=Path, required=True)
    args=p.parse_args(argv)
    try:
        dests=[x.resolve() for x in (args.questions_out,args.key_out,args.token_out)]
        if len(set(dests)) != 3 or any(x.exists() for x in (args.questions_out,args.key_out,args.token_out)):
            raise AIReviewError("public, proposed key and token report must be disjoint nonexisting files")
        specs=json.loads(args.specs.read_text(encoding="utf-8"))
        evidence=json.loads(args.evidence.read_text(encoding="utf-8"))
        public, private=build(specs,load_queue(args.queue),evidence)
        from transformers import AutoTokenizer
        tokenizer=AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
        if not getattr(tokenizer,"is_fast",False):
            raise AIReviewError("real ModernBERT fast tokenizer required")
        result=token_audit(public,lambda s: tokenizer.encode(s,add_special_tokens=True,truncation=False))
        if not result["all_pass"]:
            raise AIReviewError("at least one real full question/answer exceeds 512 tokens: "+str(result["failures"]))
        for dest in (args.questions_out,args.key_out,args.token_out):
            dest.parent.mkdir(parents=True,exist_ok=True)
        args.questions_out.write_bytes(_canonical(public))
        args.key_out.write_bytes(_canonical(private))
        result["public_packet_sha256"]=_sha(_canonical(public))
        args.token_out.write_bytes(_canonical(result))
        print(json.dumps({"status":public["status"],"research_pairs":len(public["cases"]),
                          "full_model_inputs_checked":result["model_inputs_checked"],
                          "max_full_tokens":result["maximum_full_model_tokens"],
                          "human_reviews":0,"network_eligible":False},indent=2))
        return 0
    except (AIReviewError,RealFixError,ReplayError,ChallengeError,KeyError,TypeError,ValueError,OSError,ImportError) as exc:
        p.exit(1,f"FALSUM AI REVIEW DRAFT ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
