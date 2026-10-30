"""Real-model score harness for counterfactual security PR reviews.

No model is trained by this program. The dataset is fictional and unreviewed.
The scoring adapter must be an actual local ModernBERT LoRA checkpoint; the
loader checks the official node tokenizer vectors before inference. Nothing
is uploaded or registered on Telegraph.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Callable


INTENT = "SECURITY_REVIEW_GENERAL"
FAMILY = "SECURITY_REVIEW"
RENDER_PREFIX = "### Task:\n"
RENDER_MIDDLE = "\n\n### Answer:\n"


class ModelEvaluationError(ValueError):
    """Invalid scorer, response, or security benchmark input."""


def render(prompt: str, answer: str) -> str:
    """Exact RenderForJudgment template from Telegraph V2."""
    if not isinstance(prompt, str) or not isinstance(answer, str):
        raise ModelEvaluationError("prompt and answer must both be strings")
    return RENDER_PREFIX + prompt + RENDER_MIDDLE + answer


def _score(score_fn: Callable[[str, str], float], prompt: str, answer: str) -> float:
    value = score_fn(prompt, answer)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ModelEvaluationError("scorer returned non-finite or nonnumeric output")
    return float(value)


def _split_report(items: list[dict]) -> dict:
    wins = sum(x["margin"] > 0 for x in items)
    ties = sum(x["margin"] == 0 for x in items)
    return {
        "count": len(items),
        "wins": wins,
        "ties": ties,
        "losses": len(items) - wins - ties,
        "pairwise_fraction": round((wins + ties * 0.5) / len(items), 6) if items else None,
    }


def evaluate_counterfactual(rows: list[dict], score_fn: Callable[[str, str], float], *,
                             score_ablation: bool = True) -> dict:
    """Grade a pairwise scorer on counterfactual A/B answers and prompt ablation.

    No training ever takes place. Both contexts of each rule family share the
    same candidate texts, with opposite correct labels. This catches scorers
    that ignore the prompt, independently of the writing style of the answers.
    """
    if not isinstance(rows, list) or not rows:
        raise ModelEvaluationError("benchmark must contain nonempty case rows")
    scored = []
    seen, families = set(), defaultdict(list)
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ModelEvaluationError(f"case {i}: expected object")
        case_id, split, group = row.get("id"), row.get("split"), row.get("contrast_set_id")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise ModelEvaluationError("duplicate or missing case id")
        seen.add(case_id)
        if split not in ("train", "validation", "holdout") or not isinstance(group, str) or not group:
            raise ModelEvaluationError(f"{case_id}: invalid split/group")
        prompt, good, bad = row.get("prompt"), row.get("contrast_chosen"), row.get("contrast_rejected")
        if not all(isinstance(v, str) and v.strip() for v in (prompt, good, bad)) or good == bad:
            raise ModelEvaluationError(f"{case_id}: missing/identical candidate answers")
        pos, neg = _score(score_fn, prompt, good), _score(score_fn, prompt, bad)
        entry = {"case_id": case_id, "split": split, "rule_family": group,
                 "score_chosen": pos, "score_rejected": neg, "margin": pos - neg}
        if not math.isfinite(entry["margin"]):
            raise ModelEvaluationError(f"{case_id}: non-finite score margin")
        if score_ablation:
            no_prompt_pos = _score(score_fn, "", good)
            no_prompt_neg = _score(score_fn, "", bad)
            entry["ablated_margin"] = no_prompt_pos - no_prompt_neg
            if not math.isfinite(entry["ablated_margin"]):
                raise ModelEvaluationError(f"{case_id}: non-finite ablated margin")
        scored.append(entry)
        families[(split, group)].append((row, entry))

    group_names = defaultdict(set)
    for (split, group) in families:
        group_names[group].add(split)
    if any(len(x) != 1 for x in group_names.values()):
        raise ModelEvaluationError("rule-family leakage across splits")
    for (split, group), pair in families.items():
        if len(pair) != 2:
            raise ModelEvaluationError(f"{split}/{group}: exactly two counterfactual contexts required")
        left, right = pair[0][0], pair[1][0]
        if left["contrast_chosen"] != right["contrast_rejected"] or left["contrast_rejected"] != right["contrast_chosen"]:
            raise ModelEvaluationError(f"{split}/{group}: answers are not exact counterfactual reversals")

    partitions = {split: _split_report([x for x in scored if x["split"] == split])
                  for split in ("train", "validation", "holdout")}
    if not partitions["validation"]["count"] or not partitions["holdout"]["count"]:
        raise ModelEvaluationError("independent validation and holdout partitions required")
    by_family = {}
    for (split, group), pairs in sorted(families.items()):
        a, b = pairs[0][1], pairs[1][1]
        both_win = a["margin"] > 0 and b["margin"] > 0
        by_family[group] = {"split": split, "both_contexts_correct": both_win,
                            "margins": [a["margin"], b["margin"]]}
    report = {"status": "UNREVIEWED_RESEARCH_BENCHMARK", "intent": INTENT, "family": FAMILY,
              "not_network_eligible": True, "model_training_performed": False,
              "case_count": len(scored), "rule_families": len(families),
              "splits": partitions, "counterfactual_families": by_family,
              "case_scores": scored,
              "warning": "Fictional, unreviewed PRs. Even a passing score is NOT independent accuracy or Telegraph acceptance."}
    if score_ablation:
        report["answer_only_ablation"] = {split: _split_report([
            {"margin": x["ablated_margin"]} for x in scored if x["split"] == split])
            for split in ("train", "validation", "holdout")}
    return report


def adapter_artifact_manifest(path: str | Path) -> dict:
    """Hash actual LoRA artifact bytes (not its filesystem path).

    Symlinks and non-regular files are rejected to avoid hidden external data.
    This measures *integrity*, not provenance of the training examples.
    """
    root = Path(path)
    if not root.is_dir() or root.is_symlink():
        raise ModelEvaluationError("trained LoRA adapter must be a real local directory")
    entries = []
    for file in sorted(root.rglob("*")):
        if file.is_symlink():
            raise ModelEvaluationError("adapter tree must not contain symlinks")
        if not file.is_file():
            continue
        relative = file.relative_to(root).as_posix()
        if file.stat().st_size > 2_000_000_000:
            raise ModelEvaluationError("adapter file exceeds 2 GB safety bound")
        h = hashlib.sha256()
        with file.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(block)
        entries.append({"path": relative, "bytes": file.stat().st_size, "sha256": h.hexdigest()})
    files = {x["path"] for x in entries}
    if "adapter_config.json" not in files or "adapter_model.safetensors" not in files:
        raise ModelEvaluationError("PEFT adapter_config.json and adapter_model.safetensors required")
    overall = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"sha256": overall, "files": entries, "integrity": "SHA256_OF_LOCAL_FILES_ONLY"}


class ModernBertAdapterScorer:
    """Real FP32-compatible model score source, no fabricated or cached labels.

    Requires a local trained PEFT adapter and the *official* kit on PYTHONPATH.
    Fails closed if tokenizer conformance, model loading, or node cap fails.
    """

    def __init__(self, adapter: str, *, base: str = "answerdotai/ModernBERT-base", max_tokens: int = 512):
        if not isinstance(adapter, str) or not adapter.strip() or not Path(adapter).is_dir():
            raise ModelEvaluationError("a local trained LoRA adapter directory is required")
        if type(max_tokens) is not int or not 1 <= max_tokens <= 512:
            raise ModelEvaluationError("max_tokens must be 1..512")
        try:
            import torch
            from peft import PeftModel
            from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer
            from wide_runtime.train_adapter import check_tokenizer, TOKENIZER_VECTORS
        except ImportError as exc:
            raise ModelEvaluationError("install the official Telegraph kit and its model dependencies") from exc
        cfg = AutoConfig.from_pretrained(base)
        if getattr(cfg, "model_type", "").lower() != "modernbert":
            raise ModelEvaluationError("only the official ModernBERT architecture is supported")
        if not TOKENIZER_VECTORS.is_file():
            raise ModelEvaluationError("official tokenizer conformance vectors are absent")
        self.tokenizer = AutoTokenizer.from_pretrained(base)
        check_tokenizer(self.tokenizer)
        self.torch = torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        backbone = AutoModelForSequenceClassification.from_pretrained(
            base, num_labels=1, torch_dtype=torch.float32, attn_implementation="eager")
        self.model = PeftModel.from_pretrained(backbone, adapter, is_trainable=False).to(self.device).eval()
        self.max_tokens = max_tokens

    def __call__(self, prompt: str, answer: str) -> float:
        text = render(prompt, answer)
        encoded = self.tokenizer(text, add_special_tokens=True, return_tensors="pt", truncation=False)
        if int(encoded["input_ids"].shape[-1]) > self.max_tokens:
            raise ModelEvaluationError("sample exceeds model/node token cap; refusing silent truncation")
        encoded = {k: v.to(self.device) for k, v in encoded.items() if k in ("input_ids", "attention_mask")}
        with self.torch.inference_mode():
            logits = self.model(**encoded).logits.float().reshape(-1)
        if logits.numel() != 1:
            raise ModelEvaluationError("model must emit exactly one score")
        score = float(logits[0].item())
        if not math.isfinite(score):
            raise ModelEvaluationError("model returned non-finite score")
        return score


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score draft counterfactual PRs with a REAL ModernBERT LoRA model")
    parser.add_argument("--benchmark", type=Path, default=Path("data/draft-pr-benchmark.json"))
    parser.add_argument("--casebook", type=Path, default=Path("data/draft-scenarios.json"))
    parser.add_argument("--adapter", required=True, help="trained local ModernBERT PEFT adapter path")
    parser.add_argument("--base", default="answerdotai/ModernBERT-base")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-tokens", type=int, default=512)
    args = parser.parse_args(argv)
    try:
        from .pr_benchmark import load_verified
        bench = load_verified(args.benchmark, args.casebook)
        scorer = ModernBertAdapterScorer(args.adapter, base=args.base, max_tokens=args.max_tokens)
        report = evaluate_counterfactual(bench["cases"], scorer)
        report["adapter_artifact"] = adapter_artifact_manifest(args.adapter)
        report["benchmark_sha256"] = hashlib.sha256(args.benchmark.read_bytes()).hexdigest()
        report["casebook_sha256"] = hashlib.sha256(args.casebook.read_bytes()).hexdigest()
        report["model_artifact_integrity_verified"] = True
        report["model_training_provenance_verified"] = False
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({k: v for k, v in report.items() if k != "case_scores"}, indent=2))
        return 0
    except (ModelEvaluationError, OSError, ValueError, ImportError) as exc:
        parser.exit(1, f"FALSUM MODEL EVAL ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
