"""Research-only context curriculum: append TRAIN-only hypothetical PR reversals.

Never uses validation or holdout PRs to generate training examples. This
ablation asks a narrow scientific question about context sensitivity; fictional
case labels remain unreviewed and cannot establish network eligibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .pr_benchmark import load_verified

INTENT = "SECURITY_REVIEW_GENERAL"


class CurriculumError(ValueError):
    """Training examples or a split/source trust boundary have been violated."""


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(advisory_train: Path, pilot_manifest: Path, pr_benchmark: Path,
          casebook: Path) -> tuple[list[dict], dict]:
    try:
        pilot = json.loads(pilot_manifest.read_text(encoding="utf-8"))
        advisory_rows = [json.loads(s) for s in advisory_train.read_text(encoding="utf-8").splitlines()]
        benchmark = load_verified(pr_benchmark, casebook)
    except (OSError, ValueError) as exc:
        raise CurriculumError(f"cannot verify source curriculum: {exc}") from exc
    if (not isinstance(pilot, dict) or pilot.get("intent") != INTENT
            or pilot.get("research_only") is not True
            or pilot.get("network_eligible") is not False
            or pilot.get("human_reviews") != 0
            or pilot.get("training_authorized_for_submission") is not False):
        raise CurriculumError("not an explicitly quarantined pilot manifest")
    original_train = pilot.get("partitions", {}).get("train", {})
    if (not isinstance(original_train, dict) or original_train.get("cases") != len(advisory_rows)
            or original_train.get("sha256") != _digest(advisory_train)):
        raise CurriculumError("source GHSA train file differs from its verified pilot audit")
    if len(advisory_rows) < 50 or any(not isinstance(row, dict) or
                                    set(row) != {"prompt", "chosen", "rejected"} or
                                    not all(isinstance(v, str) and v.strip() for v in row.values())
                                    for row in advisory_rows):
        raise CurriculumError("expected >=50 valid original advisory training comparisons")
    cases = benchmark["cases"]
    extra = [{"prompt": r["prompt"], "chosen": r["contrast_chosen"],
              "rejected": r["contrast_rejected"]}
             for r in cases if r["split"] == "train"]
    families = {r["contrast_set_id"] for r in cases if r["split"] == "train"}
    withheld = {r["contrast_set_id"] for r in cases if r["split"] != "train"}
    if families & withheld or len(families) < 2 or len(extra) != 2 * len(families):
        raise CurriculumError("research PR family split contamination or too few examples")
    if len(extra) != 6:
        raise CurriculumError("expected exactly six training-partition PR contrasts")
    combined = advisory_rows + extra
    if len({r["rejected"] for r in combined}) != len(combined):
        raise CurriculumError("duplicate negative response in mixed research corpus")
    if len({r["prompt"] for r in combined}) != len(combined):
        raise CurriculumError("duplicate prompt in mixed research corpus")
    manifest = {
        **pilot,
        "curriculum": "GHSA_TRAIN_PLUS_DRAFT_PR_TRAIN_ONLY",
        "source_pilot_manifest_sha256": _digest(pilot_manifest),
        "source_pr_benchmark_sha256": _digest(pr_benchmark),
        "source_casebook_sha256": _digest(casebook),
        "base_train_pairs": len(advisory_rows),
        "added_unreviewed_pr_train_pairs": len(extra),
        "withheld_pr_validation_cases": sum(r["split"] == "validation" for r in cases),
        "withheld_pr_holdout_cases": sum(r["split"] == "holdout" for r in cases),
        "used_pr_family_ids": sorted(families),
        "withheld_pr_family_ids": sorted(withheld),
        "training_authorized_for_submission": False,
        "network_eligible": False,
        "human_reviews": 0,
        "research_only": True,
        "partitions": {**pilot["partitions"], "train": {
            "cases": len(combined), "sha256": hashlib.sha256(
                "".join(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n" for row in combined)
                .encode("utf-8")).hexdigest()}},
    }
    return combined, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Append TRAIN-only unreviewed counterfactuals to research pilot")
    parser.add_argument("--advisory-train", required=True, type=Path)
    parser.add_argument("--pilot-manifest", required=True, type=Path)
    parser.add_argument("--pr-benchmark", type=Path, default=Path("data/draft-pr-benchmark.json"))
    parser.add_argument("--casebook", type=Path, default=Path("data/draft-scenarios.json"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out.exists() or args.manifest.exists() or args.out == args.manifest:
            raise CurriculumError("refusing to overwrite or alias experimental output")
        rows, report = build(args.advisory_train, args.pilot_manifest, args.pr_benchmark, args.casebook)
        payload = "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in rows)
        if hashlib.sha256(payload.encode("utf-8")).hexdigest() != report["partitions"]["train"]["sha256"]:
            raise CurriculumError("rendered training payload integrity mismatch")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
        args.manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({k: report[k] for k in
                          ("curriculum", "base_train_pairs", "added_unreviewed_pr_train_pairs",
                           "withheld_pr_validation_cases", "withheld_pr_holdout_cases")},
                         sort_keys=True))
        return 0
    except (CurriculumError, OSError, ValueError) as exc:
        parser.exit(1, f"FALSUM CONTEXT CURRICULUM ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
