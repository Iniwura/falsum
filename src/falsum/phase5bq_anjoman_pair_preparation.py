"""Prepare source-backed Anjoman preference-pair candidates without submission.

The packet is an owner-review artifact, not an eligibility claim.  Every row is
derived from the immutable Phase5BO advisory and registry snapshots, carries
source and version provenance, and is rejected if the reference resolver no
longer reproduces the frozen label.  No network upload, wallet operation or
maintainer acceptance is attempted.
"""
from __future__ import annotations

import argparse
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
from typing import Any
import unicodedata

from .phase5bo_ecosystem_semantics import (
    APPLICABLE,
    INAPPLICABLE,
    _action_for,
    _available_versions,
    _load_evidence,
    _load_protocol,
    _matching_affected,
    _reference_status,
)


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = Path("data/phase5bo-ecosystem-semantics-protocol.json")
STATUS = "PHASE5BQ_ANJOMAN_PAIR_CANDIDATE_PACKET_V2"
CURRENT_INTENT = "SECURITY_REVIEW_GENERAL"
FAMILY = "SECURITY_REVIEW"
PROVENANCE_KIND = "generated"
HISTORICAL_STATUS = "PHASE5BQ_ANJOMAN_PAIR_CANDIDATE_PACKET"
MIN_PROMPT_LENGTH = 16
MAX_PROMPT_LENGTH = 16_000
MIN_ANSWER_LENGTH = 8
MAX_ANSWER_LENGTH = 32_000
MAX_PROMPT_SIMILARITY = 0.85
MIN_PAIRED_LENGTH_RATIO = 0.65
MAX_LENGTH_SHORTCUT_ACCURACY = 0.75


class PairPreparationError(ValueError):
    """Raised when a candidate pair cannot be proven source-backed."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise PairPreparationError(message)


def _range_text(advisory: dict[str, Any], ecosystem: str, package: str) -> tuple[str, list[str]]:
    ranges: list[str] = []
    for affected in _matching_affected(advisory, ecosystem, package):
        raw_ranges = affected.get("ranges")
        if not isinstance(raw_ranges, list):
            continue
        for item in raw_ranges:
            if not isinstance(item, dict) or not isinstance(item.get("events"), list):
                continue
            opened: str | None = None
            for event in item["events"]:
                if not isinstance(event, dict) or len(event) != 1:
                    continue
                key, value = next(iter(event.items()))
                if key == "introduced" and isinstance(value, str):
                    opened = value
                elif key == "fixed" and opened is not None and isinstance(value, str):
                    ranges.append(f">={opened},<{value}")
                    opened = None
                elif key == "last_affected" and opened is not None and isinstance(value, str):
                    ranges.append(f">={opened},<={value}")
                    opened = None
                elif key == "limit" and opened is not None and value == "*":
                    ranges.append(f">={opened}")
                    opened = None
    if not ranges:
        return "no supported interval was published", []
    return "; ".join(ranges), ranges


def _scenario(ecosystem: str, version: str, ranges: list[str]) -> str:
    if "-" in version or version.casefold().endswith("pre"):
        return "Apply the ecosystem's prerelease ordering rather than comparing version text lexically."
    if len(ranges) > 1:
        return "Resolve the disjoint published branches independently; do not merge their gaps."
    if ecosystem == "PyPI" and any(ch.isalpha() for ch in version):
        return "Apply PEP 440 ordering, including this legacy or prerelease spelling."
    return "Respect the published fixed boundary and the exact package identity."


def _wrong_reason(reference: str, version: str, ranges: list[str]) -> str:
    if reference == APPLICABLE:
        if "-" in version or version.casefold().endswith("pre"):
            return "It misorders the prerelease against the stable boundary and therefore misses the affected interval."
        return "It applies the fixed boundary on the wrong side and treats an affected release as already remediated."
    fixed = {item.split(",<", 1)[1] for item in ranges if ",<" in item}
    if version in fixed:
        return "It incorrectly includes the fixed-exclusive boundary release in the affected set."
    if ranges and version.startswith("0") and all(item.split(">=", 1)[1].startswith("0") for item in ranges):
        return "It incorrectly treats a pre-introduction or legacy release as covered by the advisory."
    if len(ranges) > 1:
        return "It incorrectly carries one affected branch across a gap into a separate fixed branch."
    return "It incorrectly carries the affected interval past its published fixed release."


def _answer(
    decision: str,
    ecosystem: str,
    package: str,
    version: str,
    advisory_id: str,
    advisory: dict[str, Any],
    *,
    correct: bool,
    answer_index: int = 0,
) -> dict[str, str]:
    action = _action_for(decision)
    summary = str(advisory.get("summary") or "the published security advisory")
    severity = str((advisory.get("database_specific") or {}).get("severity") or "unspecified")
    range_text, ranges = _range_text(advisory, ecosystem, package)
    semantics = "PEP 440" if ecosystem == "PyPI" else "strict npm SemVer"
    scenario = _scenario(ecosystem, version, ranges)
    answer_headings = (
        "Review result: the exact",
        "Source-bound disposition: the exact",
        "Release-gate finding: the exact",
        "Evidence check: the exact",
        "Package review conclusion: the exact",
        "Boundary analysis: the exact",
        "Maintainer handoff: the exact",
    )
    heading = answer_headings[answer_index % len(answer_headings)]
    if correct:
        assessment = (
            f"{heading} {'affected' if decision == APPLICABLE else 'not affected'}. The "
            f"{ecosystem} package entry for {package}@{version} is resolved against {advisory_id} "
            f"({summary}; severity {severity}) under {semantics}. Published intervals: {range_text}. "
            f"{scenario}"
        )
        recommendation = (
            "Action: block this dependency or upgrade it beyond the published affected interval; "
            "do not claim exploitability from version applicability alone. Scope: this is a version-applicability finding."
            if decision == APPLICABLE else
            "Action: do not block for this advisory alone; continue checking other advisories, "
            "the dependency manifest and application-specific evidence; do not infer exploitability from this version fact. "
            "Scope: this is a version-applicability finding."
        )
    else:
        wrong_reference = APPLICABLE if decision == INAPPLICABLE else INAPPLICABLE
        assessment = (
            f"{heading} {'affected' if decision == APPLICABLE else 'not affected'}. The "
            f"{ecosystem} package entry for {package}@{version} is compared with {advisory_id} "
            f"({summary}; severity {severity}) under {semantics}. Published intervals: {range_text}. "
            f"{_wrong_reason(wrong_reference, version, ranges)}"
        )
        recommendation = (
            "Action: continue without an advisory block based on that comparison; this answer does not "
            "establish exploitability. Scope: this is a version-applicability finding."
            if decision == INAPPLICABLE else
            "Action: block or upgrade this dependency based on that comparison; this answer does not "
            "establish exploitability. Scope: this is a version-applicability finding."
        )
    paired_notes = (
        (
            "Audit note: retain the exact registry spelling and fixed endpoint in the review record.",
            "Review note: the package-level conclusion still needs application-specific reachability evidence before any exploit claim.",
        ),
        (
            "Audit note: the ecosystem comparator, not lexical order, is the reproducible basis for this release decision.",
            "Review note: this alternate disposition must not be generalized to other package releases or advisory branches.",
        ),
        (
            "Audit note: keep each affected branch separate when the advisory publishes more than one interval.",
            "Review note: a remediation decision should still be checked against the manifest and deployed dependency graph.",
        ),
        (
            "Audit note: the cited advisory summary and version range are the evidence anchor for this bounded finding.",
            "Review note: the opposing interpretation is not evidence of a runtime exploit and should be independently rechecked.",
        ),
        (
            "Audit note: the safe action is limited to the exact package identity and published version semantics shown here.",
            "Review note: confirm the registry snapshot and application context before treating this as an operational incident.",
        ),
        (
            "Audit note: preserve this boundary comparison with the source snapshot so another reviewer can replay it offline.",
            "Review note: do not infer package safety or exploitability from this single advisory decision alone.",
        ),
        (
            "Audit note: record whether the release is before, inside or beyond each published endpoint.",
            "Review note: the proposed next step remains provisional until the exact dependency graph is checked.",
        ),
    )
    correct_note, wrong_note = paired_notes[answer_index % len(paired_notes)]
    note = correct_note if correct else wrong_note
    return {"decision": decision, "action": action, "scope": "version_applicability_only", "text": assessment + " " + recommendation + " " + note}


def _wrong_decision(decision: str) -> str:
    if decision == APPLICABLE:
        return INAPPLICABLE
    if decision == INAPPLICABLE:
        return APPLICABLE
    return APPLICABLE


def _pair_id(case: dict[str, Any], advisory_meta: dict[str, Any], registry_meta: dict[str, Any]) -> str:
    material = "|".join((
        str(case["case_id"]),
        str(advisory_meta.get("sha256")),
        str(registry_meta.get("sha256")),
        str(case["target"]["version"]),
    ))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _prompt(
    case: dict[str, Any],
    advisory: dict[str, Any],
    ranges: list[str],
    range_text: str = "",
    review_index: int = 0,
) -> str:
    target = case["target"]
    # Each row gets a different, technically meaningful reviewer lens. The
    # index follows protocol order and is presentation-only: it never selects
    # the frozen reference label or an answer token.
    focuses = (
        "Check every disjoint major-line interval independently and explain why a gap must not inherit a neighboring branch.",
        "Treat the exact release as a fixed-boundary decision and state which side of each exclusive endpoint it occupies.",
        "Inspect prerelease ordering under the native comparator, then separate that result from runtime exploitability.",
        "Reconcile the package identity, advisory severity and published interval before choosing block, upgrade or review.",
        "Audit the legacy spelling as the ecosystem would parse it; do not use lexical string order as evidence.",
        "Use the cited source to show one concrete affected or fixed boundary and name the remaining uncertainty.",
        "Compare the target release with all published branches rather than collapsing them into one broad range.",
        "Write a maintainer-ready remediation recommendation whose scope is limited to this advisory's version fact.",
        "Explain how a stable release differs from a prerelease under the documented ecosystem semantics.",
        "Verify that the package metadata contains the exact target release before drawing a security conclusion.",
        "Distinguish an advisory applicability result from proof that a particular application is exploitable.",
        "Reproduce the decision from the public advisory, registry snapshot and package/version identity alone.",
        "Check the upgrade boundary and make the recommendation fail closed when the published range is unsupported.",
        "State the evidence anchor, version semantics and safe next action in a form suitable for an automated review queue.",
    )
    focus = focuses[review_index % len(focuses)]
    return (
        f"{focus} Package under review: {target['ecosystem']}:{target['package']}@{target['version']}. "
        f"Advisory: {case['advisory_id']} — {advisory.get('summary', 'a published security advisory')}. "
        f"Published interval text: {range_text}. "
        f"Use the published advisory and package metadata. State whether this exact dependency is affected, "
        f"include severity and a concrete evidence anchor, then recommend a safe next action. "
        f"Do not infer exploitability from version applicability alone. {_scenario(target['ecosystem'], target['version'], ranges)}"
    )


def _normalize_prompt(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value).casefold().split())


def _upload_row(prompt: str, chosen: dict[str, str], rejected: dict[str, str], source_url: str) -> dict[str, Any]:
    return {
        "prompt": prompt,
        "chosen": chosen["text"],
        "rejected": rejected["text"],
        "label_kind": "preference_pair",
        "intent_id": CURRENT_INTENT,
        "provenance": {"source_kind": PROVENANCE_KIND, "source_url": source_url},
    }


def _similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, left, right).ratio()


def _best_length_threshold_accuracy(rows: list[dict[str, Any]]) -> float:
    observations = [(len(row["chosen"]), 1) for row in rows] + [(len(row["rejected"]), 0) for row in rows]
    best = 0.0
    for threshold in sorted({length for length, _ in observations}):
        for reverse in (False, True):
            correct = sum((length >= threshold) == (label if not reverse else not label)
                          for length, label in observations)
            best = max(best, correct / len(observations))
    return best


def _quality_audit(rows: list[dict[str, Any]]) -> dict[str, Any]:
    prompts = [_normalize_prompt(row["prompt"]) for row in rows]
    similarities = [_similarity(left, right) for index, left in enumerate(prompts) for right in prompts[index + 1:]]
    paired_ratios = [min(len(row["chosen"]), len(row["rejected"])) / max(len(row["chosen"]), len(row["rejected"])) for row in rows]
    threshold_accuracy = _best_length_threshold_accuracy(rows)
    need(all(MIN_PROMPT_LENGTH <= len(prompt) <= MAX_PROMPT_LENGTH for prompt in prompts), "prompt length outside official bounds")
    need(all(MIN_ANSWER_LENGTH <= len(row["chosen"]) <= MAX_ANSWER_LENGTH and
             MIN_ANSWER_LENGTH <= len(row["rejected"]) <= MAX_ANSWER_LENGTH for row in rows),
         "answer length outside official bounds")
    need(max(similarities, default=0.0) < MAX_PROMPT_SIMILARITY, "near-duplicate prompt similarity reaches official rejection threshold")
    need(min(paired_ratios, default=0.0) >= MIN_PAIRED_LENGTH_RATIO, "chosen/rejected lengths are too easy to separate")
    need(threshold_accuracy <= MAX_LENGTH_SHORTCUT_ACCURACY, "a length-only threshold predicts preference too well")
    need(len({len(row["chosen"]) for row in rows}) >= 5 and len({len(row["rejected"]) for row in rows}) >= 5,
         "answer lengths are unnaturally repetitive")
    need(len({row["chosen"] for row in rows}) == len(rows)
         and len({row["rejected"] for row in rows}) == len(rows),
         "answer templates repeat across candidate rows")
    return {
        "official_prompt_length": {"minimum": MIN_PROMPT_LENGTH, "maximum": MAX_PROMPT_LENGTH},
        "official_answer_length": {"minimum": MIN_ANSWER_LENGTH, "maximum": MAX_ANSWER_LENGTH},
        "max_pairwise_prompt_similarity": max(similarities, default=0.0),
        "near_duplicate_threshold": MAX_PROMPT_SIMILARITY,
        "minimum_paired_answer_length_ratio": min(paired_ratios, default=0.0),
        "length_only_best_threshold_accuracy": threshold_accuracy,
        "length_shortcut_threshold": MAX_LENGTH_SHORTCUT_ACCURACY,
        "prompt_near_duplicate_check_passed": True,
        "answer_length_shortcut_check_passed": True,
        "answer_length_diversity_check_passed": True,
        "answer_template_diversity_check_passed": True,
    }


def _validate_upload_row(row: dict[str, Any]) -> None:
    need(set(row) == {"prompt", "chosen", "rejected", "label_kind", "intent_id", "provenance"},
         "upload row does not match the official preference-pair schema")
    need(isinstance(row["prompt"], str) and MIN_PROMPT_LENGTH <= len(row["prompt"]) <= MAX_PROMPT_LENGTH,
         "upload prompt length is outside official bounds")
    need(isinstance(row["chosen"], str) and MIN_ANSWER_LENGTH <= len(row["chosen"]) <= MAX_ANSWER_LENGTH,
         "upload chosen length is outside official bounds")
    need(isinstance(row["rejected"], str) and MIN_ANSWER_LENGTH <= len(row["rejected"]) <= MAX_ANSWER_LENGTH,
         "upload rejected length is outside official bounds")
    need(row["chosen"] != row["rejected"] and row["label_kind"] == "preference_pair"
         and row["intent_id"] == CURRENT_INTENT, "upload row has invalid preference-pair fields")
    provenance = row["provenance"]
    need(isinstance(provenance, dict) and set(provenance) == {"source_kind", "source_url"}
         and provenance["source_kind"] == PROVENANCE_KIND
         and isinstance(provenance["source_url"], str)
         and provenance["source_url"].startswith("https://"), "upload provenance is invalid")


def prepare(root: Path = ROOT) -> dict[str, Any]:
    protocol = _load_protocol(root)
    advisories, registries = _load_evidence(root, protocol)
    rows: list[dict[str, Any]] = []
    seen_questions: set[str] = set()
    seen_pairs: set[str] = set()

    for case in protocol["cases"]:
        target = case["target"]
        advisory_id = case["advisory_id"]
        ecosystem = target["ecosystem"]
        package = target["package"]
        version = target["version"]
        advisory_meta = protocol["advisories"][advisory_id]
        registry_key = f"{ecosystem}-{package}"
        registry_meta = protocol["registries"][registry_key]
        advisory = advisories[advisory_id]
        registry = registries[registry_key]

        range_text, ranges = _range_text(advisory, ecosystem, package)
        question = _prompt(case, advisory, ranges, range_text, review_index=len(rows))
        normalized_question = _normalize_prompt(question)
        need(normalized_question not in seen_questions, "duplicate normalized question")
        seen_questions.add(normalized_question)

        reference = case["reference"]["label"]
        reproduced = _reference_status(advisory, ecosystem, package, version)
        need(reproduced == reference, f"frozen reference label does not reproduce: {case['case_id']}")
        available = _available_versions(ecosystem, registry)
        need(version in available, f"candidate version missing from registry snapshot: {package}@{version}")

        pair_id = _pair_id(case, advisory_meta, registry_meta)
        need(pair_id not in seen_pairs, "duplicate pair fingerprint")
        seen_pairs.add(pair_id)
        better = _answer(reference, ecosystem, package, version, advisory_id, advisory, correct=True, answer_index=len(rows))
        worse = _answer(_wrong_decision(reference), ecosystem, package, version, advisory_id, advisory, correct=False, answer_index=len(rows))
        upload_row = _upload_row(question, better, worse, advisory_meta["source_url"])
        _validate_upload_row(upload_row)
        quality_checks = {
            "advisory_source_pinned": isinstance(advisory_meta.get("sha256"), str) and len(advisory_meta["sha256"]) == 64,
            "registry_source_pinned": isinstance(registry_meta.get("sha256"), str) and len(registry_meta["sha256"]) == 64,
            "advisory_identity_verified": advisory.get("id") == advisory_id,
            "version_exists_in_immutable_registry_snapshot": version in available,
            "reference_label_reproduced": reproduced == reference,
            "better_and_worse_are_distinct": better["decision"] != worse["decision"] and better["text"] != worse["text"],
            "both_answers_are_scope_limited": better["scope"] == worse["scope"] == "version_applicability_only",
            "scope_disclaims_exploitability": (
                "exploitability" in better["text"] and "exploitability" in worse["text"]
                and "version" in better["text"] and "version" in worse["text"]
            ),
            "official_intent_schema": upload_row["intent_id"] == CURRENT_INTENT
            and upload_row["label_kind"] == "preference_pair",
            "answer_length_comparable": min(len(upload_row["chosen"]), len(upload_row["rejected"]))
            / max(len(upload_row["chosen"]), len(upload_row["rejected"])) >= MIN_PAIRED_LENGTH_RATIO,
            "technical_evidence_and_action_contrast": (
                advisory.get("summary") in better["text"] and advisory.get("summary") in worse["text"]
                and better["action"] != worse["action"]
            ),
        }
        need(all(quality_checks.values()), f"pair quality gate failed: {case['case_id']}")
        rows.append({
            "pair_id": pair_id,
            "question": question,
            "normalized_question": normalized_question,
            "better_answer": better,
            "worse_answer": worse,
            "upload_row": upload_row,
            "published_range_text": range_text,
            "reference_label": reference,
            "provenance": {
                "advisory_id": advisory_id,
                "advisory_source_url": advisory_meta["source_url"],
                "advisory_source_sha256": advisory_meta["sha256"],
                "advisory_snapshot": advisory_meta["snapshot"],
                "registry_source_url": registry_meta["source_url"],
                "registry_source_sha256": registry_meta["sha256"],
                "registry_snapshot": registry_meta["snapshot"],
                "ecosystem": ecosystem,
                "package": package,
                "version": version,
            },
            "deduplication": {
            "normalization": "Unicode NFC, casefold and collapse whitespace",
                "unique_question_in_packet": True,
                "unique_pair_fingerprint_in_packet": True,
            },
            "quality_checks": quality_checks,
            "submission_state": "CANDIDATE_NOT_SUBMITTED",
            "human_adjudicated": False,
            "network_eligible": False,
        })

    upload_rows = [row["upload_row"] for row in rows]
    quality_audit = _quality_audit(upload_rows)
    report = {
        "schema_version": 2,
        "status": STATUS,
        "intent": CURRENT_INTENT,
        "family": FAMILY,
        "historical_status": HISTORICAL_STATUS,
        "protocol": str(PROTOCOL).replace("\\", "/"),
        "source_policy": "Pinned GitHub-reviewed advisory and immutable package-registry snapshots only",
        "candidate_pair_count": len(rows),
        "quality_gate_passed": True,
        "deduplication_passed": len(rows) == len(seen_questions) == len(seen_pairs),
        "quality_audit": quality_audit,
        "upload_schema": {
            "format": "JSON Lines, one exact object per line",
            "content_type": "application/x-ndjson",
            "intent_id": CURRENT_INTENT,
            "label_kind": "preference_pair",
            "provenance_class": "unverified_generated_with_public_source_url",
            "rows_are_not_submitted": True,
        },
        "upload_rows": upload_rows,
        "submission_state": "OWNER_REVIEW_REQUIRED_NOT_SUBMITTED",
        "human_adjudication": False,
        "network_eligibility": False,
        "rows": rows,
        "limits": [
            "These are source-backed candidate pairs, not accepted Anjoman material or maintainer-approved labels.",
            "The preference contrast is a deterministic version-applicability pair and is not human AppSec gold.",
            "No row is uploaded, signed, paid, or presented as independent adoption.",
        ],
    }
    validate(report)
    return report


def validate(report: dict[str, Any]) -> None:
    need(report.get("status") == STATUS, "invalid candidate packet status")
    rows = report.get("rows")
    need(isinstance(rows, list) and rows and report.get("quality_gate_passed") is True,
         "candidate packet is empty or not quality-gated")
    need(report.get("submission_state") == "OWNER_REVIEW_REQUIRED_NOT_SUBMITTED"
         and report.get("human_adjudication") is False
         and report.get("network_eligibility") is False,
         "candidate packet was inflated into acceptance")
    pair_ids = [row.get("pair_id") for row in rows]
    questions = [row.get("normalized_question") for row in rows]
    need(len(pair_ids) == len(set(pair_ids)) and len(questions) == len(set(questions)),
         "candidate packet contains duplicate pairs")
    upload_rows = report.get("upload_rows")
    need(isinstance(upload_rows, list) and len(upload_rows) == len(rows), "upload row count does not match candidates")
    for upload_row in upload_rows:
        _validate_upload_row(upload_row)
    _quality_audit(upload_rows)
    recorded_audit = report.get("quality_audit")
    need(isinstance(recorded_audit, dict)
         and recorded_audit.get("prompt_near_duplicate_check_passed") is True
         and recorded_audit.get("answer_length_shortcut_check_passed") is True
         and recorded_audit.get("answer_template_diversity_check_passed") is True,
         "quality audit is missing or does not record the official shortcut checks")
    for row in rows:
        need(row.get("submission_state") == "CANDIDATE_NOT_SUBMITTED"
             and row.get("human_adjudicated") is False
             and row.get("network_eligible") is False,
             "row was inflated into acceptance")
        need(all(row.get("quality_checks", {}).values()), "row quality gate failed")
        need(row.get("better_answer", {}).get("decision") != row.get("worse_answer", {}).get("decision"),
             "better and worse answers collapse")
        need("answer_token" not in json.dumps(row, sort_keys=True), "opaque answer token leaked into pair packet")


def _write_once(path: Path, report: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(),
         "pair packet output must be a new JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for row in rows
    )


def _write_jsonl_once(path: Path, rows: list[dict[str, Any]]) -> str:
    need(path.suffix == ".jsonl" and not path.exists() and not path.is_symlink(),
         "Anjoman upload preview must be a new JSONL path")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = _jsonl_bytes(rows)
    with path.open("xb") as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--jsonl-out", type=Path, help="write an exact, unsigned Anjoman JSONL upload preview")
    args = parser.parse_args(argv)
    try:
        report = prepare()
        _write_once(args.out, report)
        preview_hash = None
        if args.jsonl_out is not None:
            preview_hash = _write_jsonl_once(args.jsonl_out, report["upload_rows"])
        print(json.dumps({"status": report["status"], "candidate_pair_count": report["candidate_pair_count"],
                          "quality_gate_passed": report["quality_gate_passed"],
                          "intent_id": report["intent"],
                          "upload_preview_sha256": preview_hash,
                          "submission_state": report["submission_state"]}, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError) as exc:
        parser.exit(1, "PHASE5BQ ANJOMAN PAIR PREPARATION FAILED CLOSED: " + str(exc)[:500] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
