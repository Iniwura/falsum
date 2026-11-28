"""Phase 5BW: pin and audit an independent public Evaluators corpus.

This is an ingestion/provenance harness, not a FALSUM scorer or blind benchmark.
It verifies upstream bytes, row identities, author metadata, and published score
arithmetic, then classifies exact public advisory-ID overlap with a frozen
FALSUM source inventory. Private FALSUM material is unavailable, so candidate
rows are never promoted to held-out status.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

from falsum.phase5aj_cross_app_evidence import AuditError, git_blob, parse, require, source_bytes

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = "data/phase5bw-adversarialeval-ingestion-protocol.json"
PROTOCOL_BLOB = "7664937b1c30db9d2a7947182e36c180178fe047"
IDENTIFIER = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b",
    re.I,
)
WHITESPACE = re.compile(r"\s+")


def _load_protocol(root: Path = ROOT) -> dict:
    raw = (root / PROTOCOL_PATH).read_bytes()
    require(git_blob(raw) == PROTOCOL_BLOB, "frozen Phase5BW protocol blob changed")
    lock = parse(raw)
    require(lock.get("status") == "PHASE5BW_EXTERNAL_ADVERSARIALEVAL_INGESTION_FROZEN",
            "unexpected Phase5BW protocol status")
    return lock


def _fetch(spec: dict) -> bytes:
    raw = source_bytes(spec)
    require(len(raw) <= spec.get("max_bytes", 200_000),
            "source exceeds protocol size limit: " + spec["key"])
    return raw


def _jsonl(raw: bytes, key: str) -> list[dict]:
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise AuditError(key + ": invalid UTF-8") from exc
    require(bool(lines), key + ": empty JSONL")
    require(len(lines) <= 1_000, key + ": excessive row count")
    rows = []
    for number, line in enumerate(lines, 1):
        require(bool(line.strip()), f"{key}: blank line at {number}")
        value = parse(line.encode("utf-8"))
        require(type(value) is dict, f"{key}: row {number} is not an object")
        rows.append(value)
    return rows


def _normalise(text: str) -> str:
    return WHITESPACE.sub(" ", unicodedata.normalize("NFC", text)).strip()


def _audit_telegraph_material(pairs: list[dict], raw_jsonl: bytes, intent_id: str,
                               authors: dict[str, int]) -> dict:
    """Check the pinned public pairs against the documented Anjoman row contract.

    This is a read-only structural audit. It does not upload, sign, infer node
    provenance state, or claim that any row is eligible or active.
    """
    prompt_min, prompt_max = 16, 16_000
    answer_min, answer_max = 8, 32_000
    row_max_bytes = 64 * 1024
    lines = raw_jsonl.splitlines()
    require(len(lines) == len(pairs), "Anjoman compatibility: JSONL line count differs")
    seen_prompts = set()
    prompt_lengths, chosen_lengths, rejected_lengths = [], [], []
    row_sizes = []
    source_kinds: dict[str, int] = {}
    https_rows = 0
    intent_id_rows = 0
    label_kinds: dict[str, int] = {}

    for index, (row, raw_line) in enumerate(zip(pairs, lines), 1):
        required = {"prompt", "chosen", "rejected", "label_kind", "provenance"}
        allowed = required | {"intent_id"}
        require(type(row) is dict and required.issubset(row) and set(row).issubset(allowed),
                f"Anjoman compatibility: row {index} has unsupported fields")
        for field in ("prompt", "chosen", "rejected"):
            value = row.get(field)
            require(isinstance(value, str) and value.strip() and "\\x00" not in value,
                    f"Anjoman compatibility: row {index} has invalid {field}")
        prompt = _normalise(row["prompt"])
        chosen = _normalise(row["chosen"])
        rejected = _normalise(row["rejected"])
        require(prompt_min <= len(prompt) <= prompt_max,
                f"Anjoman compatibility: row {index} prompt length is outside documented bounds")
        require(answer_min <= len(chosen) <= answer_max and answer_min <= len(rejected) <= answer_max,
                f"Anjoman compatibility: row {index} answer length is outside documented bounds")
        require(chosen != rejected, f"Anjoman compatibility: row {index} answers are identical")
        require(prompt not in seen_prompts, "Anjoman compatibility: duplicate normalized prompt")
        seen_prompts.add(prompt)

        require(row.get("label_kind") == "preference_pair",
                f"Anjoman compatibility: row {index} is not a preference_pair")
        label_kinds[row["label_kind"]] = label_kinds.get(row["label_kind"], 0) + 1
        if "intent_id" in row:
            intent_id_rows += 1
            require(row["intent_id"] == intent_id,
                    f"Anjoman compatibility: row {index} targets a different Intent")

        provenance = row.get("provenance")
        require(type(provenance) is dict and set(provenance) == {"source_kind", "source_url"},
                f"Anjoman compatibility: row {index} provenance fields are malformed")
        source_kind = provenance.get("source_kind")
        source_url = provenance.get("source_url")
        require(isinstance(source_kind, str) and source_kind.strip(),
                f"Anjoman compatibility: row {index} source_kind is missing")
        parsed_url = urlparse(source_url) if isinstance(source_url, str) else None
        require(parsed_url is not None and parsed_url.scheme == "https" and parsed_url.netloc,
                f"Anjoman compatibility: row {index} source_url is not an absolute HTTPS URL")
        source_kinds[source_kind] = source_kinds.get(source_kind, 0) + 1
        https_rows += 1

        row_size = len(raw_line)
        require(row_size <= row_max_bytes,
                f"Anjoman compatibility: row {index} exceeds the 64 KiB row limit")
        row_sizes.append(row_size)
        prompt_lengths.append(len(prompt))
        chosen_lengths.append(len(chosen))
        rejected_lengths.append(len(rejected))

    return {
        "official_sources": {
            "material_guide": "https://anjoman.ai/docs/scoring/contribute-evaluation-data",
            "intent_catalogue": "https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md",
            "bounty": "https://github.com/telegraphprotocol/bounties/issues/96",
            "checked_date": "2026-11-28",
        },
        "intent": {
            "intent_id": intent_id,
            "kind": "judgment",
            "family": "SECURITY_REVIEW",
            "family_adapter_required": True,
            "response_shape": ["verdict", "vulnerability_count", "issues", "summary"],
        },
        "row_contract": {
            "format": "JSON Lines",
            "label_kind": "preference_pair",
            "required_fields": ["prompt", "chosen", "rejected"],
            "optional_fields": ["label_kind", "intent_id", "provenance"],
            "prompt_characters": {"minimum": prompt_min, "maximum": prompt_max},
            "answer_characters": {"minimum": answer_min, "maximum": answer_max},
            "maximum_row_bytes": row_max_bytes,
            "prompt_normalization": "Unicode NFC; collapse runs of whitespace; no case folding",
        },
        "sample_size": len(pairs),
        "structurally_compatible_rows": len(pairs),
        "structural_compatibility_verified": True,
        "normalized_unique_prompts": len(seen_prompts),
        "prompt_length_characters": {
            "minimum": min(prompt_lengths), "maximum": max(prompt_lengths),
        },
        "chosen_length_characters": {
            "minimum": min(chosen_lengths), "maximum": max(chosen_lengths),
        },
        "rejected_length_characters": {
            "minimum": min(rejected_lengths), "maximum": max(rejected_lengths),
        },
        "maximum_raw_jsonl_row_bytes": max(row_sizes),
        "label_kind_counts": label_kinds,
        "intent_id_present_rows": intent_id_rows,
        "provenance": {
            "source_kind_counts": source_kinds,
            "https_source_url_rows": https_rows,
            "node_provenance_classification": "NOT_OBSERVED_NO_UPLOAD",
            "note": "The source_kind value is preserved verbatim; no attested, admitted, eligible or active status is inferred without a node response.",
        },
        "pool_activation": {
            "minimum_distinct_contributors": 5,
            "external_dataset_authors": authors,
            "external_authors_counted_as_network_contributors": False,
            "active_snapshot_verified": False,
        },
        "submission": {
            "upload_attempted": False,
            "signature_created": False,
            "network_row_status_observed": False,
            "eligible_claimed": False,
            "ranking_use_claimed": False,
        },
    }


def _row_id(prompt: str, chosen: str, rejected: str) -> str:
    payload = "\0".join(_normalise(x) for x in (prompt, chosen, rejected)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _identifiers(value: str) -> set[str]:
    return {match.group(0).upper() for match in IDENTIFIER.finditer(value)}


def _classify_pair(identifiers: set[str], public_ids: set[str]) -> tuple[str, list[str]]:
    overlap = sorted(identifiers & public_ids)
    if overlap:
        return "PUBLIC_SOURCE_OVERLAP", overlap
    if identifiers:
        return "PUBLIC_SOURCE_DISJOINT_CANDIDATE", []
    return "UNCLASSIFIED_NO_ADVISORY_ID", []


def _wilson(correct: int, total: int, z: float = 1.96) -> tuple[float, float]:
    require(total > 0 and 0 <= correct <= total, "invalid Wilson inputs")
    p = correct / total
    d = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / d
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def _external_sources(lock: dict) -> dict[str, bytes]:
    ext = lock["external"]
    result = {}
    for original in ext["files"]:
        spec = {
            **original,
            "repo": ext["repository"],
            "commit": ext["commit"],
        }
        result[original["key"]] = _fetch(spec)
    return result


def _falsum_sources(lock: dict) -> dict[str, bytes]:
    inventory = lock["falsum_public_inventory"]
    result = {}
    for original in inventory["files"]:
        spec = {
            "key": original["path"],
            "repo": inventory["repository"],
            "commit": inventory["base_commit"],
            "path": original["path"],
            "blob": original["blob"],
            "max_bytes": 200_000,
        }
        result[original["path"]] = _fetch(spec)
    return result


def _audit_external(lock: dict, raw: dict[str, bytes]) -> dict:
    ext = lock["external"]
    expected = ext["expected"]
    require(raw["license"].decode("utf-8", "strict").startswith("MIT License"),
            "external license is not the pinned MIT license")
    readme = raw["readme"].decode("utf-8", "strict")
    freeze_report = raw["freeze_report"].decode("utf-8", "strict")
    score_report = raw["score_report"].decode("utf-8", "strict")
    registration_rule = raw["registration_rule"].decode("utf-8", "strict")
    require("77.5%" in readme and "40 pairs from 2 outside authors" in readme,
            "README no longer states the published independent test")
    require("**All 40**" in score_report and "**31**" in score_report
            and "**77.5%**" in score_report,
            "published score report does not state 31/40")
    require("more advisory ids cited" in score_report and "60%" in score_report,
            "published shortcut baseline statement is missing")
    require("80%" in registration_rule and "DO NOT REGISTER" in registration_rule,
            "frozen registration rule or its negative decision is missing")

    test_spec = next(x for x in ext["files"] if x["key"] == "test_pairs")
    meta_spec = next(x for x in ext["files"] if x["key"] == "test_metadata")
    test_sha = hashlib.sha256(raw["test_pairs"]).hexdigest()
    meta_sha = hashlib.sha256(raw["test_metadata"]).hexdigest()
    require(test_sha == test_spec["sha256"], "frozen test-set SHA-256 mismatch")
    require(meta_sha == meta_spec["sha256"], "frozen metadata SHA-256 mismatch")
    require(test_sha in freeze_report and meta_sha in freeze_report,
            "freeze report does not bind both source files")

    pairs = _jsonl(raw["test_pairs"], "test_pairs")
    metadata = _jsonl(raw["test_metadata"], "test_metadata")
    require(len(pairs) == expected["pairs"] == len(metadata),
            "pair/metadata sample size differs from frozen protocol")

    metadata_by_id = {}
    author_counts: dict[str, int] = {}
    for row in metadata:
        ident = row.get("row_id")
        require(isinstance(ident, str) and re.fullmatch(r"[0-9a-f]{64}", ident),
                "metadata row_id is malformed")
        require(ident not in metadata_by_id, "duplicate metadata row_id")
        metadata_by_id[ident] = row
        author = row.get("author")
        require(isinstance(author, str) and author, "missing reviewer identity")
        author_counts[author] = author_counts.get(author, 0) + 1
        require(row.get("split") == "test" and row.get("reviewed") is True,
                "external pair is not marked as reviewed test material")
        require(row.get("source_kind") == "ai_assisted",
                "unexpected external source class")
        require(isinstance(row.get("drafting_model"), str) and row["drafting_model"],
                "missing drafting-model disclosure")

    require(author_counts == expected["reviewers"], "reviewer counts differ from frozen protocol")
    require(sum(1 for row in metadata if row.get("source_kind") == "ai_assisted")
            == expected["ai_assisted_pairs"], "AI-assisted count differs")
    require(sum(1 for row in metadata if row.get("reviewed") is True)
            == expected["author_reviewed_pairs"], "author-reviewed count differs")

    pair_ids = []
    pair_identifiers: list[set[str]] = []
    for index, pair in enumerate(pairs, 1):
        for field in ("prompt", "chosen", "rejected"):
            require(isinstance(pair.get(field), str) and pair[field].strip(),
                    f"pair {index}: missing {field}")
        require(pair.get("label_kind") == "preference_pair",
                f"pair {index}: unexpected label kind")
        provenance = pair.get("provenance")
        require(type(provenance) is dict and provenance.get("source_kind") == "ai_assisted",
                f"pair {index}: provenance class mismatch")
        url = provenance.get("source_url")
        require(isinstance(url, str) and urlparse(url).scheme == "https",
                f"pair {index}: source URL is not HTTPS")
        ident = _row_id(pair["prompt"], pair["chosen"], pair["rejected"])
        require(ident not in pair_ids, "duplicate external pair identity")
        pair_ids.append(ident)
        meta = metadata_by_id.get(ident)
        require(meta is not None, f"pair {index}: row identity missing from metadata")
        require(meta.get("source_url") == url, f"pair {index}: provenance URL mismatch")
        pair_identifiers.append(_identifiers(
            pair["prompt"] + "\n" + pair["chosen"] + "\n" + pair["rejected"] + "\n" + url
        ))
    require(set(pair_ids) == set(metadata_by_id), "unmatched test metadata rows")
    material_compatibility = _audit_telegraph_material(
        pairs, raw["test_pairs"], ext["intent"], author_counts
    )

    raw_scores = parse(raw["raw_scores"])
    require(type(raw_scores) is list and len(raw_scores) == len(pairs),
            "raw score sample size differs")
    score_by_id = {}
    correct = incorrect = ties = 0
    for record in raw_scores:
        require(type(record) is dict, "raw score row is not an object")
        ident = record.get("row_id")
        require(isinstance(ident, str) and ident in metadata_by_id,
                "raw score row references an unknown pair")
        require(ident not in score_by_id, "duplicate raw score row_id")
        require(record.get("file") == "data/test/security_review.test.jsonl",
                "raw score row references another input file")
        chosen, rejected = record.get("chosen"), record.get("rejected")
        require(type(chosen) in (int, float) and type(rejected) in (int, float)
                and math.isfinite(chosen) and math.isfinite(rejected),
                "nonfinite or invalid raw model score")
        measured = 1.0 if chosen > rejected else 0.5 if chosen == rejected else 0.0
        require(record.get("correct") == measured,
                "raw correct flag disagrees with the two published scores")
        score_by_id[ident] = record
        if measured == 1.0:
            correct += 1
        elif measured == 0.0:
            incorrect += 1
        else:
            ties += 1
    require(set(score_by_id) == set(pair_ids), "raw scores do not cover every frozen pair")
    require((correct, incorrect, ties) == (
        expected["published_adapter_correct"],
        expected["published_adapter_incorrect"],
        expected["published_adapter_ties"],
    ), "published adapter result differs from the frozen raw scores")
    accuracy = 100.0 * correct / len(pairs)
    low, high = _wilson(correct, len(pairs))
    require(round(accuracy, 1) == expected["published_adapter_accuracy_percent"],
            "published adapter percentage differs")
    require([round(100 * low, 1), round(100 * high, 1)]
            == expected["published_adapter_wilson_95_percent"],
            "published Wilson interval differs")

    return {
        "repository": ext["repository"],
        "commit": ext["commit"],
        "license": "MIT",
        "files": ext["files"],
        "sample_sizes": {
            "pairs": len(pairs),
            "reviewers": author_counts,
            "author_reviewed_ai_assisted": len(metadata),
            "fully_human_written": 0,
        },
        "telegraph_material_compatibility": material_compatibility,
        "published_external_adapter": {
            "correct": correct,
            "incorrect": incorrect,
            "ties": ties,
            "accuracy_percent": round(accuracy, 1),
            "wilson_95_percent": [round(100 * low, 1), round(100 * high, 1)],
            "raw_score_arithmetic_replayed": True,
            "adapter_inference_reproduced": False,
        },
        "published_shortcut_baseline": {
            "strongest_accuracy_percent": expected["published_strongest_shortcut_percent"],
            "source": "external score report",
            "raw_shortcut_predictions_replayed": False,
        },
        "pair_identifiers": pair_identifiers,
        "pair_ids": pair_ids,
    }


def _audit_overlap(lock: dict, external: dict, own_raw: dict[str, bytes]) -> dict:
    inventory = lock["falsum_public_inventory"]
    own_ids: set[str] = set()
    for raw in own_raw.values():
        own_ids.update(_identifiers(raw.decode("utf-8", "strict")))
    require(len(own_ids) == inventory["expected_identifier_count"],
            "FALSUM public inventory identifier count changed")

    overlap_rows = []
    candidate_rows = []
    unclassified = 0
    external_ids: set[str] = set()
    for index, (ident, ids) in enumerate(zip(external["pair_ids"], external["pair_identifiers"]), 1):
        external_ids.update(ids)
        classification, overlap = _classify_pair(ids, own_ids)
        if classification == "PUBLIC_SOURCE_OVERLAP":
            overlap_rows.append({"row_number": index, "row_id": ident, "identifiers": overlap})
        elif classification == "PUBLIC_SOURCE_DISJOINT_CANDIDATE":
            ghsa = sorted(x for x in ids if x.startswith("GHSA-"))
            candidate_rows.append({"row_number": index, "row_id": ident, "ghsa": ghsa})
        else:
            unclassified += 1

    expected_overlap_ids = sorted(inventory["expected_public_overlap_identifiers"])
    observed_overlap_ids = sorted({x for row in overlap_rows for x in row["identifiers"]})
    expected_overlap_rows = inventory["expected_public_overlap_pairs"]
    expected_candidates = inventory["expected_public_source_disjoint_candidate_pairs"]
    expected_candidates = sorted(expected_candidates, key=lambda x: x["row_number"])
    observed_candidates = sorted(candidate_rows, key=lambda x: x["row_number"])
    require(observed_overlap_ids == expected_overlap_ids,
            "public overlap identifier set differs from frozen protocol")
    require([{"row_number": x["row_number"], "row_id": x["row_id"]} for x in overlap_rows]
            == expected_overlap_rows, "public overlap pair roster differs")
    require(observed_candidates == expected_candidates,
            "public-source-disjoint candidate roster differs")
    candidate_ghsa = sorted({g for row in candidate_rows for g in row["ghsa"]})
    require(len(external_ids) == 11, "external advisory identifier count changed")
    require(len(candidate_rows) == 9 and len(candidate_ghsa) == 6,
            "public-source-disjoint candidate sample differs")
    require(unclassified == inventory["expected_unclassified_pairs"],
            "unclassified pair count differs")
    require(len(overlap_rows) + len(candidate_rows) + unclassified == len(external["pair_ids"]),
            "pair classification is not exhaustive")

    return {
        "falsum_public_inventory": {
            "base_commit": inventory["base_commit"],
            "files": inventory["files"],
            "advisory_identifier_count": len(own_ids),
        },
        "external_advisory_identifier_count": len(external_ids),
        "public_overlap": {
            "identifiers": observed_overlap_ids,
            "pairs": overlap_rows,
            "unique_advisory_families": 1,
        },
        "public_source_disjoint_candidates": {
            "pairs": observed_candidates,
            "pair_count": len(candidate_rows),
            "distinct_ghsa_identifiers": candidate_ghsa,
            "distinct_ghsa_count": len(candidate_ghsa),
            "private_overlap": inventory["private_pool_overlap"],
            "eligible_as_blind_heldout": False,
        },
        "unclassified_pairs_without_advisory_identifiers": unclassified,
    }


def audit(root: Path = ROOT) -> dict:
    lock = _load_protocol(root)
    external_raw = _external_sources(lock)
    own_raw = _falsum_sources(lock)
    external = _audit_external(lock, external_raw)
    overlap = _audit_overlap(lock, external, own_raw)
    return {
        "status": "PHASE5BW_EXTERNAL_ADVERSARIALEVAL_INGESTION_VERIFIED",
        "protocol_git_blob_sha1": PROTOCOL_BLOB,
        "external_corpus": {k: v for k, v in external.items()
                            if k not in {"pair_identifiers", "pair_ids"}},
        "public_source_overlap": overlap,
        "interpretation": {
            "falsum_scored": False,
            "matched_falsum_baseline_comparison": False,
            "independent_human_gold": False,
            "complete_source_disjoint_holdout": False,
            "telegraph_material_schema_compatibility": external["telegraph_material_compatibility"]["structural_compatibility_verified"],
            "telegraph_material_acceptance": False,
            "telegraph_ranking_change": False,
            "independent_falsum_reproduction": False,
        },
        "limits": lock["limits"],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    result = audit()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(json.dumps({
        "status": result["status"],
        "external_pairs": result["external_corpus"]["sample_sizes"]["pairs"],
        "external_adapter": result["external_corpus"]["published_external_adapter"],
        "public_overlap_pairs": len(result["public_source_overlap"]["public_overlap"]["pairs"]),
        "public_disjoint_candidate_pairs": result["public_source_overlap"]["public_source_disjoint_candidates"]["pair_count"],
        "public_disjoint_ghsa_count": result["public_source_overlap"]["public_source_disjoint_candidates"]["distinct_ghsa_count"],
        "unclassified_pairs": result["public_source_overlap"]["unclassified_pairs_without_advisory_identifiers"],
        "private_overlap": result["public_source_overlap"]["public_source_disjoint_candidates"]["private_overlap"],
        "falsum_scored": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
