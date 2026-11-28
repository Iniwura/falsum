"""Phase 5CC: correct AdversarialEval source identity without answer-text leakage.

Phase 5BW remains the immutable upstream-byte and score-arithmetic audit.
This phase reuses its authenticated inputs but derives source identity only
from the prompt and declared provenance URL. Candidate answer text is never
used to establish source disjointness.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import phase5bw_adversarialeval_ingestion as bw


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = "data/phase5cc-adversarialeval-source-scope-protocol.json"
PROTOCOL_BLOB = "b065bc98083abb173552e8a4e755e53685bbf1c7"
STATUS = "PHASE5CC_ADVERSARIALEVAL_SOURCE_IDENTITY_AUDIT"


class SourceScopeError(ValueError):
    """Raised when the frozen source-identity contract cannot be reproduced."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise SourceScopeError(message)


def frozen_protocol(root: Path = ROOT) -> dict[str, Any]:
    raw = (root / PROTOCOL_PATH).read_bytes()
    need(bw.git_blob(raw) == PROTOCOL_BLOB, "Phase 5CC protocol blob changed after freeze")
    protocol = bw.parse(raw)
    need(type(protocol) is dict
         and protocol.get("schema_version") == 1
         and protocol.get("status") == "PHASE5CC_ADVERSARIALEVAL_SOURCE_IDENTITY_ROSTER_FROZEN",
         "invalid Phase 5CC protocol")
    need(protocol.get("upstream_phase5bw", {}).get("git_blob_sha1") == bw.PROTOCOL_BLOB,
         "Phase 5CC no longer binds the authenticated Phase 5BW protocol")
    selection = protocol.get("selection_policy")
    need(type(selection) is dict
         and selection.get("source_identity_fields") == ["prompt", "provenance.source_url"]
         and selection.get("excluded_from_source_identity") == ["chosen", "rejected"]
         and selection.get("heldout_eligible") is False
         and selection.get("candidate_inference_before_freeze") is False,
         "Phase 5CC source-selection policy was weakened")
    return protocol


def source_identifiers(prompt: str, source_url: str) -> set[str]:
    """Return only source-anchored identifiers, never identifiers from answers."""
    return bw._identifiers(prompt + "\n" + source_url)


def answer_only_identifiers(chosen: str, rejected: str,
                            source_ids: set[str]) -> set[str]:
    """Diagnostic only: these identifiers must not affect source classification."""
    return bw._identifiers(chosen + "\n" + rejected) - source_ids


def audit(root: Path = ROOT) -> dict[str, Any]:
    protocol = frozen_protocol(root)
    upstream = bw._load_protocol(root)
    external_raw = bw._external_sources(upstream)
    own_raw = bw._falsum_sources(upstream)

    # Re-run the upstream's complete authentication, metadata, row-identity,
    # author-disclosure, and published raw-score arithmetic checks first.
    external = bw._audit_external(upstream, external_raw)
    pairs = bw._jsonl(external_raw["test_pairs"], "test_pairs")
    metadata = bw._jsonl(external_raw["test_metadata"], "test_metadata")
    need(len(pairs) == protocol["external"]["expected_pair_count"] == 40,
         "external pair count differs from the precommitted roster")
    need(len(metadata) == protocol["external"]["expected_metadata_count"] == 40,
         "external metadata count differs from the precommitted roster")

    metadata_by_id = {row["row_id"]: row for row in metadata}
    need(len(metadata_by_id) == len(metadata), "duplicate metadata row identity")
    public_ids: set[str] = set()
    for raw in own_raw.values():
        public_ids.update(bw._identifiers(raw.decode("utf-8", "strict")))
    inventory = protocol["falsum_public_inventory"]
    need(len(public_ids) == inventory["expected_advisory_identifier_count"] == 35,
         "frozen FALSUM public inventory identifier count changed")

    source_union: set[str] = set()
    overlap_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    answer_only_rows: list[dict[str, Any]] = []
    unclassified = 0
    seen_pair_ids: set[str] = set()

    for index, pair in enumerate(pairs, 1):
        prompt = pair["prompt"]
        chosen = pair["chosen"]
        rejected = pair["rejected"]
        provenance = pair["provenance"]
        source_url = provenance["source_url"]
        row_id = bw._row_id(prompt, chosen, rejected)
        need(row_id not in seen_pair_ids, f"duplicate pair identity at row {index}")
        seen_pair_ids.add(row_id)
        meta = metadata_by_id.get(row_id)
        need(meta is not None and meta.get("source_url") == source_url,
             f"pair {index} no longer matches its author metadata")

        identifiers = source_identifiers(prompt, source_url)
        source_union.update(identifiers)
        answer_only = sorted(answer_only_identifiers(chosen, rejected, identifiers))
        classification, overlap = bw._classify_pair(identifiers, public_ids)

        if answer_only:
            answer_only_rows.append({
                "row_number": index,
                "row_id": row_id,
                "source_url": source_url,
                "answer_only_identifiers": answer_only,
                "classification": (
                    "PUBLIC_SOURCE_OVERLAP" if classification == "PUBLIC_SOURCE_OVERLAP"
                    else "PUBLIC_SOURCE_DISJOINT_CANDIDATE" if classification == "PUBLIC_SOURCE_DISJOINT_CANDIDATE"
                    else "UNCLASSIFIED_NO_SOURCE_IDENTIFIER"
                ),
            })
        if classification == "PUBLIC_SOURCE_OVERLAP":
            overlap_rows.append({
                "row_number": index,
                "row_id": row_id,
                "identifiers": overlap,
            })
        elif classification == "PUBLIC_SOURCE_DISJOINT_CANDIDATE":
            candidate_rows.append({
                "row_number": index,
                "row_id": row_id,
                "identifiers": sorted(identifiers),
            })
        else:
            unclassified += 1

    expected = protocol["expected"]
    need(len(source_union) == expected["source_identifier_count"] == 10,
         "source-anchored identifier count changed")
    need(overlap_rows == expected["public_overlap"],
         "public-overlap source roster differs from precommit")
    need(candidate_rows == expected["public_source_disjoint_candidates"],
         "public-source-disjoint candidate roster differs from precommit")
    need(unclassified == expected["unclassified_pair_count"] == 31,
         "unclassified source count differs from precommit")
    need(answer_only_rows == expected["answer_only_identifier_rows"],
         "answer-only identifier diagnostic differs from precommit")
    candidate_ghsa = sorted({
        identifier
        for row in candidate_rows
        for identifier in row["identifiers"]
        if identifier.startswith("GHSA-")
    })
    need(len(candidate_rows) == 8 and len(candidate_ghsa) == 6,
         "corrected candidate sample size or advisory-family count changed")
    need(len(overlap_rows) + len(candidate_rows) + unclassified == len(pairs),
         "source classification is not exhaustive")

    previous = upstream["falsum_public_inventory"]
    return {
        "status": STATUS,
        "protocol_git_blob_sha1": PROTOCOL_BLOB,
        "upstream_phase5bw_protocol_git_blob_sha1": bw.PROTOCOL_BLOB,
        "external_corpus": {
            "repository": external["repository"],
            "commit": external["commit"],
            "license": external["license"],
            "sample_sizes": external["sample_sizes"],
            "published_external_adapter": external["published_external_adapter"],
            "published_shortcut_baseline": external["published_shortcut_baseline"],
        },
        "source_identity": {
            "rule": "PROMPT_AND_PROVENANCE_URL_ONLY",
            "answer_text_used_for_source_identity": False,
            "source_identifier_count": len(source_union),
            "falsum_public_inventory": {
                "base_commit": previous["base_commit"],
                "advisory_identifier_count": len(public_ids),
            },
            "public_overlap": {
                "pairs": overlap_rows,
                "pair_count": len(overlap_rows),
            },
            "public_source_disjoint_candidates": {
                "pairs": candidate_rows,
                "pair_count": len(candidate_rows),
                "distinct_ghsa_identifiers": candidate_ghsa,
                "distinct_ghsa_count": len(candidate_ghsa),
                "private_pool_overlap": inventory["private_pool_overlap"],
                "eligible_as_blind_heldout": False,
            },
            "unclassified_pairs_without_source_identifiers": unclassified,
            "answer_only_identifier_rows": answer_only_rows,
            "legacy_answer_inclusive_candidate_count": 9,
            "corrected_candidate_count": 8,
            "legacy_unclassified_count": 30,
            "corrected_unclassified_count": 31,
        },
        "interpretation": {
            "source_identity_corrected": True,
            "falsum_scored": False,
            "matched_falsum_baseline_comparison": False,
            "candidate_inference_run": False,
            "complete_source_disjoint_holdout": False,
            "private_pool_overlap_known": False,
            "telegraph_material_acceptance": False,
            "telegraph_ranking_change": False,
            "independent_falsum_reproduction": False,
        },
        "limits": protocol["limits"],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    report = audit()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    source = report["source_identity"]
    print(json.dumps({
        "status": report["status"],
        "pairs": report["external_corpus"]["sample_sizes"]["pairs"],
        "source_identifiers": source["source_identifier_count"],
        "public_overlap_pairs": source["public_overlap"]["pair_count"],
        "public_source_disjoint_candidates": source["public_source_disjoint_candidates"]["pair_count"],
        "distinct_ghsa_identifiers": source["public_source_disjoint_candidates"]["distinct_ghsa_count"],
        "unclassified_pairs": source["unclassified_pairs_without_source_identifiers"],
        "private_pool_overlap": source["public_source_disjoint_candidates"]["private_pool_overlap"],
        "eligible_as_blind_heldout": source["public_source_disjoint_candidates"]["eligible_as_blind_heldout"],
        "falsum_scored": report["interpretation"]["falsum_scored"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
