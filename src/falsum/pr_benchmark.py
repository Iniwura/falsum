"""Honest, source-linked hypothetical pull-request security-review benchmark.

These fixtures are deliberately fictional. They demonstrate review preconditions
and answer-only shortcut risks; they do NOT establish expert ground truth,
security exploitability, or Telegraph eligibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

from .scenarios import read_casebook, verify_source_snapshots

TOKEN = re.compile(r"[a-z][a-z0-9_]{1,}", re.I)
CREDENTIAL = re.compile(r"(?i)(?:ghp_[a-z0-9]{36,}|github_pat_[a-z0-9_]{30,}|AKIA[A-Z0-9]{16}|sk_live_[a-z0-9]{16,})")
SPLITS = ("train", "validation", "holdout")


class PRBenchmarkError(ValueError):
    """A case or a scoring run fails the benchmark's integrity checks."""


def load_verified(path: str | Path, casebook_path: str | Path) -> dict:
    """Recheck original human-review status, source snapshots, and case lineage."""
    path, casebook_path = Path(path), Path(casebook_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        book = read_casebook(casebook_path)
    except (OSError, ValueError) as exc:
        raise PRBenchmarkError(f"cannot read source benchmark: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1 or data.get("status") != "HYPOTHETICAL_DRAFT_NOT_REVIEWED":
        raise PRBenchmarkError("benchmark must be explicitly labeled as draft")
    if hashlib.sha256(casebook_path.read_bytes()).hexdigest() != data.get("source_casebook_sha256"):
        raise PRBenchmarkError("casebook bytes changed since benchmark was authored")
    source_errors = verify_source_snapshots(book, casebook_path.parent)
    if source_errors:
        raise PRBenchmarkError("source excerpt integrity failed: " + "; ".join(source_errors))
    originals = {row["id"]: row for row in book["cases"]}
    rows = data.get("cases")
    if not isinstance(rows, list) or len(rows) != len(originals):
        raise PRBenchmarkError("benchmark must contain every original scenario exactly once")
    seen, patches, per_source, per_family = set(), set(), defaultdict(set), defaultdict(set)
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise PRBenchmarkError(f"case[{index}] not an object")
        key = row.get("id")
        if not isinstance(key, str) or key in seen or key not in originals or key != row.get("casebook_id"):
            raise PRBenchmarkError(f"case[{index}] unknown or duplicate scenario id")
        seen.add(key)
        original = originals[key]
        for field in ("rule_family", "category", "split", "source_ids", "chosen", "rejected"):
            if row.get(field) != original.get(field):
                raise PRBenchmarkError(f"{key}: {field} diverged from source scenario")
        if row.get("review_status") != "draft" or original["review_status"] != "draft":
            raise PRBenchmarkError(f"{key}: cannot promote cases automatically")
        patch, prompt, context, file_path = (row.get(x) for x in ("patch", "prompt", "deployment_evidence", "file_path"))
        if not all(isinstance(x, str) for x in (patch, prompt, context, file_path)):
            raise PRBenchmarkError(f"{key}: missing patch/prompt/environment")
        if (not patch.startswith("diff --git a/") or not file_path or file_path.startswith("/") or ".." in Path(file_path).parts
                or f"b/{file_path}" not in patch or "@@" not in patch or len(patch) > 3000):
            raise PRBenchmarkError(f"{key}: invalid scoped fictional diff")
        if (patch not in prompt or context not in prompt or len(context) < 30
                or "```diff" not in prompt):
            raise PRBenchmarkError(f"{key}: prompt lost its diff or deployment preconditions")
        if CREDENTIAL.search(patch + prompt):
            raise PRBenchmarkError(f"{key}: possible real credential detected")
        digest = hashlib.sha256(patch.encode("utf-8")).hexdigest()
        if digest in patches:
            raise PRBenchmarkError(f"{key}: repeated diff")
        patches.add(digest)
        if row["split"] not in SPLITS:
            raise PRBenchmarkError(f"{key}: unsupported split")
        per_family[row["rule_family"]].add(row["split"])
        for source_id in row["source_ids"]:
            per_source[source_id].add(row["split"])
    if seen != set(originals):
        raise PRBenchmarkError("missing scenario rows")
    # Matched contrast answers must swap labels under opposite deployment facts.
    by_group = defaultdict(list)
    for row in rows:
        if row.get('contrast_set_id') != row['rule_family'] or row.get('contrast_design') != 'COUNTERFACTUAL_DRAFT':
            raise PRBenchmarkError(f"{row['id']}: missing counterfactual provenance")
        if any(not isinstance(row.get(k), str) or len(row[k]) < 65 for k in ('contrast_chosen', 'contrast_rejected')):
            raise PRBenchmarkError(f"{row['id']}: contrast answers must be substantive")
        if row['contrast_chosen'] == row['contrast_rejected']:
            raise PRBenchmarkError(f"{row['id']}: identical contrast answers")
        by_group[row['contrast_set_id']].append(row)
    for group, matched in by_group.items():
        if len(matched) != 2:
            raise PRBenchmarkError(f"{group}: expected exactly two contexts")
        left, right = matched
        if left['contrast_chosen'] != right['contrast_rejected'] or left['contrast_rejected'] != right['contrast_chosen']:
            raise PRBenchmarkError(f"{group}: context reversals do not swap the exact same answers")
    for tag, groups in (("rule family", per_family), ("source", per_source)):
        for key, splits in groups.items():
            if len(splits) != 1:
                raise PRBenchmarkError(f"{tag} {key}: split leakage")
    return data


def _tokenize(value: str) -> list[str]:
    return TOKEN.findall(value.casefold())


class SurfaceNaiveBayes:
    """Deliberately weak *answer-only* audit; NOT a deployable evaluator.

    Chosen/rejected labels from training only. Never sees prompts or targets
    from the validation and holdout partitions during fitting.
    """

    def __init__(self):
        self.bags = [Counter(), Counter()]
        self.totals = [0, 0]
        self.vocab: set[str] = set()
        self.fitted = False

    def fit(self, pairs: list[dict]) -> None:
        if not pairs or any(p.get("split") != "train" for p in pairs):
            raise PRBenchmarkError("training can use only nonempty train split")
        for row in pairs:
            for label, field in ((1, "chosen"), (0, "rejected")):
                items = _tokenize(row[field])
                self.bags[label].update(items)
                self.totals[label] += len(items)
                self.vocab.update(items)
        self.fitted = True

    def score(self, text: str) -> float:
        if not self.fitted:
            raise PRBenchmarkError("fit baseline before scoring")
        words = _tokenize(text)
        if not words:
            return 0.0
        vocab = max(1, len(self.vocab))
        # Normalize by length so token count cannot trivially decide.
        return sum(math.log((self.bags[1][word] + 1) / (self.totals[1] + vocab)) -
                   math.log((self.bags[0][word] + 1) / (self.totals[0] + vocab))
                   for word in words) / len(words)


def baseline_report(rows: list[dict], *, use_contrast: bool = False) -> dict:
    """Check shortcut-learning on held-out scenarios; never present as model accuracy."""
    model = SurfaceNaiveBayes()
    chosen_field = 'contrast_chosen' if use_contrast else 'chosen'
    rejected_field = 'contrast_rejected' if use_contrast else 'rejected'
    model.fit([{**x, 'chosen': x[chosen_field], 'rejected': x[rejected_field]} for x in rows if x['split'] == 'train'])
    scores = {}
    for split in ("validation", "holdout"):
        group = [x for x in rows if x["split"] == split]
        if not group:
            raise PRBenchmarkError(f"missing {split} partition")
        wins = ties = 0
        failures = []
        for item in group:
            chosen = model.score(item[chosen_field])
            rejected = model.score(item[rejected_field])
            wins += chosen > rejected
            ties += chosen == rejected
            if chosen <= rejected:
                failures.append(item["id"])
        scores[split] = {"n": len(group), "pairwise_fraction": round((wins + 0.5 * ties)/len(group), 4),
                         "not_ranked_correctly": failures}
    return {"baseline": "answer_only_multinomial_nb", "dataset": "counterfactual" if use_contrast else "original", "feature_access": "answer text only; no prompt/diff/source",
            "fit_count": sum(x["split"] == "train" for x in rows), "results": scores,
            "caution": "Tiny, hypothetical, unreviewed partitions. This is shortcut-leakage diagnosis, NOT real evaluator accuracy."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit fictional security PR benchmark without claiming model accuracy")
    parser.add_argument("benchmark", type=Path)
    parser.add_argument("--source-casebook", type=Path, default=Path("data/draft-scenarios.json"))
    parser.add_argument("--report-out", type=Path)
    args = parser.parse_args(argv)
    try:
        data = load_verified(args.benchmark, args.source_casebook)
        report = {"status":"DRAFT_ONLY", "case_count":len(data["cases"]),
                  "reviewed":0, "eligible":0, "model_trained":False,
                  "baseline_diagnostic":baseline_report(data["cases"]),
                  "counterfactual_diagnostic":baseline_report(data["cases"], use_contrast=True)}
        contents = json.dumps(report, indent=2, sort_keys=True) + "\n"
        print(contents, end="")
        if args.report_out:
            args.report_out.parent.mkdir(parents=True, exist_ok=True)
            args.report_out.write_text(contents, encoding="utf-8")
        return 0
    except (PRBenchmarkError, OSError, ValueError) as exc:
        parser.exit(1, f"FALSUM PR benchmark ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
