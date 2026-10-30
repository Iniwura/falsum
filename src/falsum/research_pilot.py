"""Quarantine checks for an exploratory, non-eligible ModernBERT training run.

This checks internal evidence lineage, split completeness, and the exact JSONL
input handed to the upstream Telegraph V2 trainer. It is NOT a human review or
approval to register a scorer. Use only with pinned and audited research data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

INTENT = "SECURITY_REVIEW_GENERAL"
EXPECTED_STATUSES = {"affected", "unaffected"}
SPLITS = ("train", "validation", "holdout")
UPSTREAM_PIN = "5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e"
GHSA_PIN = "4af30eafd57e3bd9a0b4865dee2ced6f611de33f"
GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.I)


class PilotError(ValueError):
    """A source/row/partition contradiction stops exploratory training."""


def _load(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PilotError(f"unreadable or malformed JSON {path.name}: {exc}") from exc


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(queue_path: str | Path, data_dir: str | Path) -> dict:
    """Check an exact quarantined dataset plus three rendered train/val/test JSONLs.

    The prior pipeline MUST run audit_reproducibility/build_grounded against
    pinned advisory bytes. This module checks the resulting TRAINER input against
    those audited outputs and refuses accidental split mixing or promotion.
    """
    queue_path, root = Path(queue_path), Path(data_dir)
    queue = _load(queue_path)
    if not isinstance(queue, dict) or queue.get("schema_version") != 1 or not isinstance(queue.get("advisories"), list):
        raise PilotError("invalid research advisory queue")
    rows_by_id = {}
    split_by_advisory = {}
    split_by_package = {}
    for source in queue["advisories"]:
        if not isinstance(source, dict) or not GHSA.fullmatch(str(source.get("id", ""))):
            raise PilotError("queue contains an invalid advisory ID")
        advisory, split = source["id"], source.get("split")
        if advisory in split_by_advisory or split not in SPLITS:
            raise PilotError("duplicate GHSA or missing split")
        family = (str(source.get("ecosystem", "")).casefold(), str(source.get("package", "")).casefold())
        if not all(family):
            raise PilotError("missing package identity")
        if family in split_by_package and split_by_package[family] != split:
            raise PilotError(f"package family crosses train/test: {family}")
        split_by_advisory[advisory] = split
        split_by_package[family] = split
    benchmark_file = root / "grounded" / "DRAFT-grounded-benchmark.json"
    benchmark = _load(benchmark_file)
    if (not isinstance(benchmark, dict) or benchmark.get("status") != "QUARANTINED_DRAFT_ONLY"
            or benchmark.get("independent_human_reviews") != 0
            or benchmark.get("telegraph_eligible") is not False
            or benchmark.get("trained_model") is not False):
        raise PilotError("benchmark is missing explicit research-only attestations")
    grounded, missing = benchmark.get("grounded"), benchmark.get("insufficient_evidence")
    if not isinstance(grounded, list) or not isinstance(missing, list) or len(grounded) != 2 * len(split_by_advisory):
        raise PilotError("grounded case count is inconsistent with advisory queue")
    if len(missing) != len(split_by_advisory):
        raise PilotError("insufficient-evidence control count is inconsistent")
    families = defaultdict(set)
    full_ids = set()
    for row in grounded:
        if not isinstance(row, dict):
            raise PilotError("grounded row is not an object")
        case_id = row.get("id")
        advisory = row.get("advisory_id")
        split = row.get("split")
        if not isinstance(case_id, str) or case_id in full_ids:
            raise PilotError("duplicate or missing case ID")
        full_ids.add(case_id)
        if advisory not in split_by_advisory or split != split_by_advisory[advisory]:
            raise PilotError(f"wrong split or advisory on {case_id}")
        if (row.get("review_status") != "draft" or row.get("evidence_availability") != "present"
                or row.get("expected_status") not in EXPECTED_STATUSES):
            raise PilotError(f"non-draft or unsupported training row {case_id}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(row.get("source_sha256", ""))):
            raise PilotError(f"missing source checksum on {case_id}")
        prompt, chosen, rejected = (row.get(k) for k in ("prompt", "chosen", "rejected"))
        if not all(isinstance(v, str) and len(v.strip()) >= 30 for v in (prompt, chosen, rejected)) or chosen == rejected:
            raise PilotError(f"invalid prompt/response on {case_id}")
        if "Published affected-version events:" not in prompt:
            raise PilotError(f"missing published range evidence on {case_id}")
        families[advisory].add(row["expected_status"])
        rows_by_id[case_id] = row
    if any(states != EXPECTED_STATUSES for states in families.values()):
        raise PilotError("each advisory must include affected and unaffected controls")
    if len({x.get("id") for x in missing if isinstance(x, dict)}) != len(missing):
        raise PilotError("duplicate missing-evidence control")
    for row in missing:
        if not isinstance(row, dict) or row.get("advisory_id") not in split_by_advisory:
            raise PilotError("unknown missing-evidence advisory")
        if row.get("review_status") != "draft" or row.get("evidence_availability") != "absent":
            raise PilotError("non-draft missing-evidence control")
        if row.get("split") != split_by_advisory[row["advisory_id"]]:
            raise PilotError("insufficient-evidence control crosses splits")
        if row.get("id") != row["advisory_id"].lower() + "-affected-missing-evidence":
            raise PilotError("missing-evidence control cannot be mapped to affected source case")
    partitions = {}
    for split in SPLITS:
        file = root / "grounded" / f"DRAFT-grounded-{split}.jsonl"
        try:
            lines = file.read_text(encoding="utf-8").splitlines()
            triplets = [json.loads(line) for line in lines]
        except (OSError, ValueError) as exc:
            raise PilotError(f"malformed rendered {split} JSONL: {exc}") from exc
        expected = [{k: r[k] for k in ("prompt", "chosen", "rejected")}
                    for r in grounded if r["split"] == split]
        if triplets != expected or not triplets:
            raise PilotError(f"{split} JSONL does not match audited source-grounded cases")
        partitions[split] = {"cases": len(triplets), "sha256": _hash(file)}
    if partitions["train"]["cases"] < 50 or partitions["validation"]["cases"] < 4 or partitions["holdout"]["cases"] < 4:
        raise PilotError("insufficient independent split sizes for this pilot")
    if len({x["sha256"] for x in partitions.values()}) != 3:
        raise PilotError("same partition input reused")
    return {
        "intent": INTENT,
        "research_only": True,
        "training_authorized_for_submission": False,
        "network_eligible": False,
        "human_reviews": 0,
        "upstream_trainer_commit": UPSTREAM_PIN,
        "upstream_advisory_commit": GHSA_PIN,
        "advisories": len(split_by_advisory),
        "missing_evidence_controls_not_trained": len(missing),
        "queue_sha256": _hash(queue_path),
        "benchmark_sha256": _hash(benchmark_file),
        "partitions": partitions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit only quarantined research data before a CPU training pilot")
    parser.add_argument("queue", type=Path)
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = audit(args.queue, args.data_dir)
        if args.manifest.exists():
            raise PilotError("refusing to overwrite pilot manifest")
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (PilotError, OSError, ValueError) as exc:
        parser.exit(1, f"FALSUM RESEARCH PILOT ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
