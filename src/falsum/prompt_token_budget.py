"""ModernBERT tokenizer capacity audit for public, unlabelled pre-fix prompts.

A passed budget never means evaluator accuracy or eligibility. Full
prompt/answer token limits must still be enforced by the scorer at inference.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .model_eval import render

INTENT = "SECURITY_REVIEW_GENERAL"
MODEL = "answerdotai/ModernBERT-base"
TOKEN_LIMIT = 512
ANSWER_RESERVE = 124
BOUNDARY_RESERVE = 4
MAX_TASK_TOKENS = TOKEN_LIMIT - ANSWER_RESERVE - BOUNDARY_RESERVE


class TokenBudgetError(ValueError):
    """Reject forged data or a prompt too long for answer reservation."""


def audit_prompts(manifest: dict, tokenize) -> dict:
    if (not isinstance(manifest, dict)
            or manifest.get("status") != "UNREVIEWED_PUBLIC_PRE_FIX_CHALLENGE_NO_ANSWERS"
            or manifest.get("intent") != INTENT
            or manifest.get("sealed_holdout") is not False
            or manifest.get("model_training_authorized") is not False
            or manifest.get("evaluation_authorized") is not False
            or manifest.get("network_eligible") is not False
            or manifest.get("independent_human_reviews") != 0
            or manifest.get("tokenizer_512_verified") is not False):
        raise TokenBudgetError("input must be a quarantined public-only challenge manifest")
    prompts = manifest.get("prompts")
    if not isinstance(prompts, list) or not prompts or len(prompts) > 100:
        raise TokenBudgetError("expected bounded, nonempty public prompts")
    ids = set()
    rows = []
    for i, item in enumerate(prompts):
        if not isinstance(item, dict) or set(item) != {"challenge_id", "prompt"}:
            raise TokenBudgetError("public model prompt contains non-prompt or answer metadata")
        case_id, prompt = item["challenge_id"], item["prompt"]
        if (not isinstance(case_id, str) or not case_id or case_id in ids
                or not isinstance(prompt, str) or not prompt.startswith("Review this excerpt")
                or "Source excerpt" not in prompt):
            raise TokenBudgetError(f"invalid or duplicate prompt at index {i}")
        ids.add(case_id)
        # Identical V2 Task/Answer renderer to the actual scorer.
        tokens = tokenize(render(prompt, ""))
        if not isinstance(tokens, list) or not tokens or any(type(t) is not int or t < 0 for t in tokens):
            raise TokenBudgetError(f"{case_id}: invalid nonnegative tokenizer integer ids")
        count = len(tokens)
        rows.append({"challenge_id": case_id, "task_template_tokens": count,
                     "reserved_for_answer": ANSWER_RESERVE,
                     "boundary_safety": BOUNDARY_RESERVE,
                     "within_budget": count <= MAX_TASK_TOKENS})
    failures = [r["challenge_id"] for r in rows if not r["within_budget"]]
    return {
        "schema_version": 1,
        "status": "MODEL_TOKEN_BUDGET_ONLY_NOT_EVALUATION",
        "model": MODEL, "render_contract": "Telegraph V2 Task/Answer",
        "token_limit": TOKEN_LIMIT, "reserved_for_answer": ANSWER_RESERVE,
        "boundary_safety": BOUNDARY_RESERVE, "max_task_tokens": MAX_TASK_TOKENS,
        "checked": len(rows), "passes": len(rows) - len(failures),
        "failures": failures, "all_pass": not failures,
        "max_observed_task_tokens": max(r["task_template_tokens"] for r in rows),
        "case_token_counts": rows,
        "network_eligible": False, "independent_human_reviews": 0,
        "eval_accuracy_measured": False, "sealed_holdout": False,
        "notice": "Token budget only. Never silently truncate. Actual answer+prompt must be checked at inference.",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Check real tokenizer budget for unlabelled pre-fix prompts")
    p.add_argument("--prompts", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.out.exists() or args.out.resolve() == args.prompts.resolve():
            raise TokenBudgetError("refusing to overwrite existing prompt/budget report")
        data = json.loads(args.prompts.read_text(encoding="utf-8"))
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(MODEL)
        if not getattr(tokenizer, "is_fast", False):
            raise TokenBudgetError("ModernBERT fast tokenizer required")
        def encode(value):
            return tokenizer.encode(value, add_special_tokens=True, truncation=False)
        report = audit_prompts(data, encode)
        report["source_prompt_sha256"] = hashlib.sha256(args.prompts.read_bytes()).hexdigest()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({k: report[k] for k in (
            "status", "checked", "passes", "max_observed_task_tokens",
            "max_task_tokens", "all_pass")}, indent=2))
        return 0 if report["all_pass"] else 1
    except (TokenBudgetError, OSError, ValueError, TypeError, ImportError) as exc:
        p.exit(2, f"FALSUM TOKEN BUDGET ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
