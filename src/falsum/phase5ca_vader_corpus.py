"""Phase 5CA: immutable VADER human-expert response corpus ingestion.

This phase freezes and audits a public, third-party human-scored benchmark.
It does not train or infer a FALSUM model, upload material, or claim private-pool
source disjointness. Raw model responses remain in the upstream CC-BY dataset.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import itertools
import json
import math
from collections import Counter
from pathlib import Path
import re
from statistics import mean
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = Path("data/phase5ca-vader-corpus-protocol.json")
PROTOCOL_GIT_BLOB_SHA1 = "7a12ad6411544047988b41e8e0c9e2f7446fc37c"
DATASET_BASE = "https://huggingface.co/datasets/AfterQuery/vader/resolve/"
MODELS = (
    "claude-3.7-sonnet",
    "gemini-2.5-pro",
    "gpt-4.1",
    "gpt-4.5",
    "o3",
    "grok-3-beta",
)
VADER_FIELDS = (
    "Case", "ID", "Repository", "CWE", "Severity", "Submitted At",
    "Approved At", "Description",
)
GRADED_FIELDS = (
    "Case", "ID", "Repository", "CWE", "Severity", "Description",
    *tuple(field for model in MODELS for field in (
        model, model + "-explanation", model + "-remediation",
        model + "-other", model + "-comment",
    )),
    *tuple(model + "-rating" for model in MODELS),
)
SEVERITY_LABELS = {
    "1": "very low", "2": "low", "3": "medium", "4": "high", "5": "critical",
}
SEVERITY_NUMBERS = {value: key for key, value in SEVERITY_LABELS.items()}
MIN_PAIR_MARGIN = 2.0
MAX_DOWNLOAD_BYTES = 8_000_000


class VaderCorpusError(ValueError):
    """Raised when the frozen third-party corpus cannot be authenticated."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise VaderCorpusError(message)


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def strict_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaderCorpusError("malformed frozen protocol JSON") from exc


def load_protocol(root: Path = ROOT) -> dict:
    raw = (root / PROTOCOL_PATH).read_bytes()
    need(git_blob_sha1(raw) == PROTOCOL_GIT_BLOB_SHA1, "Phase 5CA corpus/split protocol changed after freeze")
    obj = strict_json(raw)
    need(isinstance(obj, dict)
         and obj.get("schema_version") == 1
         and obj.get("status") == "PHASE5CA_VADER_CORPUS_AND_SOURCE_SPLIT_PREINFERENCE_FROZEN"
         and obj.get("freeze_base_commit") == "d7c072ce155b33fcb906df55d2025f9efc167906",
         "invalid Phase 5CA pre-inference protocol")
    ds = obj.get("dataset", {})
    need(ds.get("repository") == "AfterQuery/vader"
         and ds.get("revision") == "9bef4b3b1994ce138d8a043b68ab0d8a81d8472d"
         and ds.get("license") == "CC-BY-4.0",
         "VADER source identity or license changed")
    need(obj.get("selection", {}).get("join_vader_and_graded_files_by_ID_only") is True
         and obj.get("selection", {}).get("selection_rule_frozen_before_candidate_changes") is True
         and obj.get("selection", {}).get("selection_does_not_use_human_scores_or_model_answers") is True
         and obj.get("selection", {}).get("malformed_csv_records_are_excluded_without_repair") is True
         and obj.get("selection", {}).get("report_malformed_record_numbers_and_ids") is True,
         "stable-ID join or score-blind source selection weakened")
    need(obj.get("safety_and_claim_limits", {}).get("vader_used_for_model_training") is False
         and obj.get("safety_and_claim_limits", {}).get("model_inference_performed") is False
         and obj.get("safety_and_claim_limits", {}).get("official_submission") is False,
         "Phase 5CA safety boundary changed")
    need(obj.get("private_material_boundary", {}).get("private_anjoman_source_overlap") == "UNKNOWN"
         and obj.get("private_material_boundary", {}).get("claim_fully_disjoint_from_private_anjoman_material") is False,
         "private Anjoman overlap must remain explicitly unknown")
    return obj


def _download(path: str, expected_blob: str, max_bytes: int, revision: str) -> tuple[bytes, dict]:
    need(path in ("vader.csv", "graded.csv"), "unapproved VADER source path")
    url = DATASET_BASE + revision + "/" + path + "?download=true"
    request = Request(url, headers={
        "Accept": "text/csv",
        "User-Agent": "FALSUM-phase5ca-vader-corpus/1.0",
    })
    with urlopen(request, timeout=60) as response:
        need(response.status == 200, "VADER source returned a non-200 status")
        final = urlparse(response.geturl())
        host = (final.hostname or "").lower()
        allowed_host = (
            host == "huggingface.co" or host.endswith(".huggingface.co")
            or host == "hf.co" or host.endswith(".hf.co")
        )
        need(final.scheme == "https" and allowed_host, "VADER source redirected outside approved HTTPS hosts")
        raw = response.read(max_bytes + 1)
    need(0 < len(raw) <= max_bytes, path + " exceeded the frozen download byte cap")
    blob = git_blob_sha1(raw)
    need(blob == expected_blob, path + " Git blob SHA-1 does not match the frozen Hugging Face revision")
    return raw, {
        "path": path,
        "bytes": len(raw),
        "git_blob_sha1": blob,
        "sha256": sha256(raw),
        "revision": revision,
        "final_host": host,
    }


def _read_csv(raw: bytes, expected_fields: tuple[str, ...], label: str) -> tuple[list[dict[str, str]], dict]:
    try:
        text = raw.decode("utf-8-sig", "strict")
        reader = csv.DictReader(
            io.StringIO(text, newline=""),
            restkey="__EXTRA_FIELDS__",
            restval=None,
        )
        need(tuple(reader.fieldnames or ()) == expected_fields, label + " header differs from frozen schema")
        rows: list[dict[str, str]] = []
        malformed = []
        for record_number, row in enumerate(reader, start=1):
            extra = row.pop("__EXTRA_FIELDS__", None)
            if extra:
                malformed.append({
                    "record_number": record_number,
                    "id": row.get("ID", ""),
                    "extra_field_count": len(extra),
                    "extra_field_lengths": [len(str(value)) for value in extra[:8]],
                })
                continue
            if not all(isinstance(value, str) for value in row.values()):
                malformed.append({
                    "record_number": record_number,
                    "id": row.get("ID", ""),
                    "extra_field_count": 0,
                    "reason": "non_string_or_missing_field",
                })
                continue
            rows.append(row)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise VaderCorpusError(label + " is not a valid UTF-8 CSV") from exc
    need(bool(rows) or bool(malformed), label + " has no data records")
    return rows, {
        "physical_records": len(rows) + len(malformed),
        "valid_records": len(rows),
        "malformed_records": len(malformed),
        "malformed_examples": malformed[:30],
    }


def canonical_repository(value: str) -> str:
    need(isinstance(value, str) and value.strip(), "missing repository identity")
    raw = value.strip().rstrip("#").strip()
    if raw.startswith("git@github.com:"):
        raw = "https://github.com/" + raw.split(":", 1)[1]
    elif "://" not in raw:
        raw = "https://github.com/" + raw.lstrip("/")
    parsed = urlparse(raw)
    need(parsed.scheme == "https" and (parsed.hostname or "").lower() in ("github.com", "www.github.com"),
         "repository identity is not a canonical GitHub URL: " + value[:120])
    parts = [part for part in parsed.path.split("/") if part]
    need(len(parts) >= 2, "GitHub repository path lacks owner/repository")
    owner, repo = parts[0].strip(), parts[1].strip()
    if repo.endswith(".git"):
        repo = repo[:-4]
    safe = re.compile(r"^[A-Za-z0-9_.-]+$")
    need(bool(safe.fullmatch(owner)) and bool(safe.fullmatch(repo)),
         "invalid GitHub owner/repository identity")
    return owner.lower() + "/" + repo.lower()


def _case_number(value: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise VaderCorpusError("invalid VADER case number") from exc
    need(number > 0, "VADER case number must be positive")
    return number


def _stable_id(value: str) -> str:
    need(isinstance(value, str) and value.isdigit() and len(value) >= 10,
         "VADER stable ID must be the published numeric record ID")
    return value


def _cwes(value: str) -> tuple[str, ...]:
    found = tuple(sorted(set(re.findall(r"CWE-\d+", value.upper()))))
    need(bool(found), "VADER record has no parseable CWE identifier")
    return found


def _severity(value: str, *, numeric_allowed: bool) -> str:
    raw = value.strip().lower()
    if numeric_allowed and raw in SEVERITY_LABELS:
        return SEVERITY_LABELS[raw]
    need(raw in SEVERITY_NUMBERS, "unknown VADER severity: " + value[:40])
    return raw


def _number(value: str, label: str, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise VaderCorpusError("missing or nonnumeric " + label) from exc
    need(math.isfinite(number) and 0 <= number <= maximum,
         label + " outside its published score range")
    return number


def _model_response(row: dict[str, str], model: str) -> dict:
    answer = row.get(model, "")
    need(isinstance(answer, str), model + " response field is malformed")
    explanation = _number(row.get(model + "-explanation", ""), model + " explanation score", 2)
    remediation = _number(row.get(model + "-remediation", ""), model + " remediation score", 5)
    other = _number(row.get(model + "-other", ""), model + " other score", 3)
    total = _number(row.get(model + "-rating", ""), model + " total score", 10)
    need(abs((explanation + remediation + other) - total) < 1e-6,
         model + " component scores do not sum to the published total")
    try:
        parsed = json.loads(answer)
        strict_json_ok = isinstance(parsed, dict)
    except (TypeError, json.JSONDecodeError):
        strict_json_ok = False
    return {
        "answer": answer,
        "answer_sha256": sha256(answer.encode("utf-8")),
        "explanation": explanation,
        "remediation": remediation,
        "other": other,
        "total": total,
        "strict_json_object": strict_json_ok,
        "answer_present": bool(answer.strip()),
    }


def _holdout_bucket(repository: str) -> int:
    salt = b"FALSUM-PHASE5CA-VADER-HOLDOUT-v1\0"
    digest = hashlib.sha256(salt + repository.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % 5


def _score_summary(cases: list[dict]) -> dict:
    result = {}
    for model in MODELS:
        rows = [case["responses"][model] for case in cases]
        result[model] = {
            "n": len(rows),
            "mean_total": round(mean(x["total"] for x in rows), 6) if rows else None,
            "mean_explanation": round(mean(x["explanation"] for x in rows), 6) if rows else None,
            "mean_remediation": round(mean(x["remediation"] for x in rows), 6) if rows else None,
            "mean_other": round(mean(x["other"] for x in rows), 6) if rows else None,
            "strict_json_objects": sum(x["strict_json_object"] for x in rows),
            "nonempty_responses": sum(x["answer_present"] for x in rows),
            "empty_responses": sum(not x["answer_present"] for x in rows),
        }
    return result


def _pairwise_summary(cases: list[dict]) -> dict:
    total = strong = near_tie = tie = 0
    by_split = {
        "reserved_holdout": {"total": 0, "strong_margin_ge_2": 0, "near_tie": 0, "tie": 0},
        "non_holdout": {"total": 0, "strong_margin_ge_2": 0, "near_tie": 0, "tie": 0},
    }
    for case in cases:
        split = "reserved_holdout" if case["reserved_holdout"] else "non_holdout"
        values = [case["responses"][model]["total"] for model in MODELS]
        for left, right in itertools.combinations(values, 2):
            margin = abs(left - right)
            total += 1
            by_split[split]["total"] += 1
            if margin >= MIN_PAIR_MARGIN:
                strong += 1
                by_split[split]["strong_margin_ge_2"] += 1
            elif margin == 0:
                tie += 1
                by_split[split]["tie"] += 1
            else:
                near_tie += 1
                by_split[split]["near_tie"] += 1
    return {
        "all_pairs": total,
        "strong_derived_preferences_margin_ge_2": strong,
        "near_ties_excluded": near_tie,
        "exact_ties_excluded": tie,
        "by_split": by_split,
        "label_origin": "DERIVED_FROM_PUBLISHED_HUMAN_EXPERT_TOTAL_SCORES_NOT_ORIGINAL_PAIRWISE_LABELS",
    }


def build_report(vader_rows: list[dict[str, str]], graded_rows: list[dict[str, str]],
                 protocol: dict, file_metadata: list[dict],
                 file_parse_diagnostics: dict | None = None) -> tuple[dict, dict]:
    file_parse_diagnostics = file_parse_diagnostics or {}
    vader_by_id: dict[str, dict] = {}
    graded_by_id: dict[str, dict] = {}
    for row in vader_rows:
        ident = _stable_id(row.get("ID", ""))
        need(ident not in vader_by_id, "duplicate stable ID in vader.csv")
        vader_by_id[ident] = row
    for row in graded_rows:
        ident = _stable_id(row.get("ID", ""))
        need(ident not in graded_by_id, "duplicate stable ID in graded.csv")
        graded_by_id[ident] = row

    vader_ids, graded_ids = set(vader_by_id), set(graded_by_id)
    common_ids = sorted(vader_ids & graded_ids, key=int)
    vader_only = sorted(vader_ids - graded_ids, key=int)
    graded_only = sorted(graded_ids - vader_ids, key=int)
    known_public = set(protocol["known_public_falsum_source_inventory"]["repositories"])
    matched: list[dict] = []
    excluded_records = []
    case_number_mismatches = []
    for ident in common_ids:
        source = vader_by_id[ident]
        scored = graded_by_id[ident]
        try:
            source_repo = canonical_repository(source["Repository"])
            scored_repo = canonical_repository(scored["Repository"])
            source_cwe = _cwes(source["CWE"])
            scored_cwe = _cwes(scored["CWE"])
            source_severity = _severity(source["Severity"], numeric_allowed=False)
            scored_severity = _severity(scored["Severity"], numeric_allowed=True)
            source_description = "\n".join(line.rstrip() for line in source["Description"].splitlines()).strip()
            graded_description = "\n".join(line.rstrip() for line in scored["Description"].splitlines()).strip()
        except (KeyError, VaderCorpusError) as exc:
            excluded_records.append({
                "id": ident,
                "reason": "invalid_source_metadata",
                "detail": str(exc),
                "vader_repository": source.get("Repository", ""),
                "graded_repository": scored.get("Repository", ""),
                "vader_cwe": source.get("CWE", ""),
                "graded_cwe": scored.get("CWE", ""),
                "vader_severity": source.get("Severity", ""),
                "graded_severity": scored.get("Severity", ""),
            })
            continue
        if (source_repo != scored_repo or source_cwe != scored_cwe
                or source_severity != scored_severity or source_description != graded_description):
            excluded_records.append({
                "id": ident,
                "reason": "repository_or_CWE_or_severity_mismatch",
                "vader_repository": source_repo,
                "graded_repository": scored_repo,
                "vader_cwe": list(source_cwe),
                "graded_cwe": list(scored_cwe),
                "vader_severity": source_severity,
                "graded_severity": scored_severity,
                "description_matches": source_description == graded_description,
            })
            continue
        try:
            source_case = _case_number(source["Case"])
            graded_case = _case_number(scored["Case"])
        except (KeyError, VaderCorpusError) as exc:
            excluded_records.append({
                "id": ident,
                "reason": "invalid_source_metadata",
                "detail": str(exc),
                "vader_case": source.get("Case", ""),
                "graded_case": scored.get("Case", ""),
            })
            continue
        if source_case != graded_case:
            case_number_mismatches.append({
                "id": ident, "vader_case": source_case, "graded_case": graded_case,
            })
        try:
            responses = {model: _model_response(scored, model) for model in MODELS}
        except VaderCorpusError as exc:
            excluded_records.append({"id": ident, "reason": "invalid_model_response_or_score", "detail": str(exc)})
            continue
        repo = source_repo
        bucket = _holdout_bucket(repo)
        reserved = bucket == 0 and repo not in known_public
        matched.append({
            "id": ident,
            "case": source_case,
            "graded_case": graded_case,
            "repository": repo,
            "repository_sha256": sha256(repo.encode("utf-8")),
            "cwe": list(source_cwe),
            "severity": source_severity,
            "description_sha256": sha256(source_description.encode("utf-8")),
            "responses": responses,
            "reserved_holdout": reserved,
            "known_public_overlap": repo in known_public,
        })

    holdout = [x for x in matched if x["reserved_holdout"]]
    holdout_repos = sorted({x["repository"] for x in holdout})
    public_overlaps = sorted({x["repository"] for x in matched if x["known_public_overlap"]})
    complete_case_count = sum(
        all(case["responses"][model]["answer_present"] for model in MODELS)
        for case in matched
    )
    cwe_counts = Counter(cwe for case in matched for cwe in case["cwe"])
    severity_counts = Counter(case["severity"] for case in matched)
    score_summary = _score_summary(matched)
    pairwise = _pairwise_summary(matched)
    roster = [{
        "id": x["id"],
        "vader_case": x["case"],
        "graded_case": x["graded_case"],
        "repository_sha256": x["repository_sha256"],
        "cwe": x["cwe"],
        "severity": x["severity"],
    } for x in holdout]
    roster_sha = sha256(canonical_json(roster))
    case_roster = [{
        "id": x["id"], "repository_sha256": x["repository_sha256"],
        "cwe": x["cwe"], "severity": x["severity"],
    } for x in matched]
    matched_case_sha = sha256(canonical_json(case_roster))
    excluded_identity = any(
        record.get("reason") == "repository_or_CWE_or_severity_mismatch"
        for record in excluded_records
    )
    invalid_source_metadata_excluded = any(
        record.get("reason") == "invalid_source_metadata"
        for record in excluded_records
    )
    invalid_response_excluded = any(
        record.get("reason") == "invalid_model_response_or_score"
        for record in excluded_records
    )
    vader_diag = file_parse_diagnostics.get("vader_csv", {})
    graded_diag = file_parse_diagnostics.get("graded_csv", {})
    malformed_csv_excluded = bool(
        vader_diag.get("malformed_records", 0) or graded_diag.get("malformed_records", 0)
    )
    warnings = []
    for label, diagnostic in (("vader.csv", vader_diag), ("graded.csv", graded_diag)):
        malformed_count = diagnostic.get("malformed_records", 0)
        if malformed_count:
            warnings.append(f"{label}: {malformed_count} malformed records excluded")
    if case_number_mismatches:
        warnings.append("case_number_mismatches_reported_not_used_for_join")
    if excluded_identity:
        warnings.append("source_metadata_identity_mismatches_excluded")
    if invalid_source_metadata_excluded:
        warnings.append("invalid_source_metadata_records_excluded")
    if invalid_response_excluded:
        warnings.append("invalid_model_response_or_score_records_excluded")
    if vader_only or graded_only:
        warnings.append("unmatched_stable_IDs_excluded")
    minimum_cases = protocol["selection"]["minimum_matched_case_count_for_benchmark_ready"]
    minimum_holdout = protocol["selection"]["minimum_reserved_holdout_cases"]
    minimum_repos = protocol["selection"]["minimum_reserved_holdout_repositories"]
    ready_reasons = []
    if len(vader_rows) != protocol["expected"]["cases_per_source_file"]:
        ready_reasons.append("vader_csv_row_count_differs_from_frozen_expectation")
    if len(graded_rows) != protocol["expected"]["cases_per_source_file"]:
        ready_reasons.append("graded_csv_row_count_differs_from_frozen_expectation")
    if len(matched) < minimum_cases:
        ready_reasons.append("matched_case_count_below_frozen_minimum")
    if len(holdout) < minimum_holdout:
        ready_reasons.append("reserved_holdout_case_count_below_frozen_minimum")
    if len(holdout_repos) < minimum_repos:
        ready_reasons.append("reserved_holdout_repository_count_below_frozen_minimum")
    if excluded_identity:
        ready_reasons.append("source_metadata_identity_mismatches_excluded")
    if invalid_source_metadata_excluded:
        ready_reasons.append("invalid_source_metadata_excluded")
    if invalid_response_excluded:
        ready_reasons.append("invalid_model_response_or_score_records_excluded")
    if malformed_csv_excluded:
        ready_reasons.append("malformed_csv_records_excluded")
    if vader_only or graded_only:
        ready_reasons.append("unmatched_stable_IDs_excluded")
    report = {
        "schema_version": 1,
        "status": "PHASE5CA_VADER_CORPUS_INGESTED_CANDIDATE_NOT_RUN",
        "dataset": protocol["dataset"],
        "dataset_revision": protocol["dataset"]["revision"],
        "source_files": file_metadata,
        "source_row_counts": {
            "vader_csv": len(vader_rows),
            "graded_csv": len(graded_rows),
            "vader_csv_physical_records": vader_diag.get("physical_records", len(vader_rows)),
            "graded_csv_physical_records": graded_diag.get("physical_records", len(graded_rows)),
            "vader_csv_malformed_records": vader_diag.get("malformed_records", 0),
            "graded_csv_malformed_records": graded_diag.get("malformed_records", 0),
        },
        "alignment": {
            "join_key": "ID",
            "vader_unique_ids": len(vader_ids),
            "graded_unique_ids": len(graded_ids),
            "matched_ids": len(common_ids),
            "matched_source_score_records": len(matched),
            "vader_only_ids": vader_only,
            "graded_only_ids": graded_only,
            "excluded_records": excluded_records,
            "source_identity_mismatches_excluded": [
                record for record in excluded_records
                if record.get("reason") == "repository_or_CWE_or_severity_mismatch"
            ],
            "invalid_source_metadata_excluded": [
                record for record in excluded_records
                if record.get("reason") == "invalid_source_metadata"
            ],
            "csv_parse_diagnostics": file_parse_diagnostics,
            "case_number_mismatch_count": len(case_number_mismatches),
            "case_number_mismatch_examples": case_number_mismatches[:20],
        },
        "corpus": {
            "matched_cases": len(matched),
            "unique_repositories": len({x["repository"] for x in matched}),
            "model_count": len(MODELS),
            "models": list(MODELS),
            "published_human_scored_responses": len(matched) * len(MODELS),
            "complete_six_model_cases": complete_case_count,
            "nonempty_model_responses": sum(x["answer_present"] for case in matched for x in case["responses"].values()),
            "empty_model_responses": sum(not x["answer_present"] for case in matched for x in case["responses"].values()),
            "cwe_case_counts": dict(sorted(cwe_counts.items())),
            "severity_case_counts": dict(sorted(severity_counts.items())),
            "published_score_summary": score_summary,
            "derived_pairwise_summary": pairwise,
            "matched_case_roster_sha256": matched_case_sha,
        },
        "source_disjointness": {
            "known_public_inventory_completeness": protocol["known_public_falsum_source_inventory"]["completeness"],
            "known_public_source_overlap_repositories": public_overlaps,
            "reserved_holdout_cases": len(holdout),
            "reserved_holdout_repositories": len(holdout_repos),
            "reserved_holdout_roster_sha256": roster_sha,
            "reserved_holdout_source_disjoint_from_listed_public_falsum_sources": not bool(
                set(holdout_repos) & known_public
            ),
            "private_anjoman_source_overlap": "UNKNOWN",
            "fully_disjoint_from_private_anjoman_material": False,
            "fully_disjoint_from_model_pretraining": False,
        },
        "benchmark_readiness": {
            "ready_for_next_candidate_stage": not ready_reasons,
            "reasons": ready_reasons,
            "warnings": warnings,
            "candidate_scores_exist": False,
            "candidate_training_on_vader": False,
            "candidate_inference_performed": False,
            "verdict_only_baseline_run": False,
            "context_aware_baseline_run": False,
            "human_expert_reference": "published VADER total and component scores",
            "human_expert_reference_is_original_pairwise_data": False,
        },
        "claim_limits": {
            "model_answers_are_human_authored": False,
            "published_scores_reflect_at_least_two_blind_expert_evaluators_per_response_per_paper": True,
            "raw_individual_rater_scores_available": False,
            "source_disjointness_claim_scope": "ONLY_LISTED_PUBLIC_FALSUM_SOURCE_INVENTORY",
            "private_anjoman_overlap_unknown": True,
            "raw_responses_written_to_report": False,
            "third_party_code_or_tests_executed": False,
            "network_upload": False,
            "official_submission": False,
            "wallet_or_signature_action": False,
            "paid_api_calls": False,
            "telegraph_network_improvement_claim": False,
        },
        "next_action": (
            "If benchmark_readiness passes, reconstruct bounded original source context for reserved cases, "
            "freeze exact case/answer bytes and token-fit exclusions, then score the unchanged research-only "
            "ModernBERT candidate and both predeclared baselines on identical prompt/answer pairs. "
            "Private Anjoman overlap remains unknown until a legitimate per-row export is available."
        ),
    }
    roster_doc = {
        "schema_version": 1,
        "status": "PHASE5CA_RESERVED_HOLDOUT_ROSTER_NO_CANDIDATE_SCORES",
        "dataset_revision": protocol["dataset"]["revision"],
        "join_key": "ID",
        "case_count": len(roster),
        "roster_sha256": roster_sha,
        "cases": roster,
        "private_anjoman_overlap": "UNKNOWN",
        "candidate_inference_performed": False,
    }
    return report, roster_doc


def run(root: Path = ROOT) -> tuple[dict, dict]:
    protocol = load_protocol(root)
    revision = protocol["dataset"]["revision"]
    source_specs = {x["path"]: x for x in protocol["source_files"]}
    vader_raw, vader_meta = _download(
        "vader.csv", source_specs["vader.csv"]["git_blob_sha1"],
        source_specs["vader.csv"]["max_bytes"], revision,
    )
    graded_raw, graded_meta = _download(
        "graded.csv", source_specs["graded.csv"]["git_blob_sha1"],
        source_specs["graded.csv"]["max_bytes"], revision,
    )
    vader_rows, vader_parse = _read_csv(vader_raw, VADER_FIELDS, "vader.csv")
    graded_rows, graded_parse = _read_csv(graded_raw, GRADED_FIELDS, "graded.csv")
    return build_report(
        vader_rows,
        graded_rows,
        protocol,
        [vader_meta, graded_meta],
        {"vader_csv": vader_parse, "graded_csv": graded_parse},
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authenticate and freeze the VADER human-scored external corpus")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--roster", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.out.resolve() == args.roster.resolve() or args.out.exists() or args.roster.exists():
            raise VaderCorpusError("refuse output overwrite or path alias")
        report, roster = run(args.root)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.roster.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        args.roster.write_text(json.dumps(roster, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": report["status"],
            "vader_rows": report["source_row_counts"]["vader_csv"],
            "graded_rows": report["source_row_counts"]["graded_csv"],
            "matched_cases": report["corpus"]["matched_cases"],
            "vader_malformed_records": report["source_row_counts"]["vader_csv_malformed_records"],
            "graded_malformed_records": report["source_row_counts"]["graded_csv_malformed_records"],
            "holdout_cases": report["source_disjointness"]["reserved_holdout_cases"],
            "strong_derived_preferences": report["corpus"]["derived_pairwise_summary"]["strong_derived_preferences_margin_ge_2"],
            "benchmark_ready": report["benchmark_readiness"]["ready_for_next_candidate_stage"],
            "private_anjoman_overlap": "UNKNOWN",
            "candidate_inference_performed": False,
        }, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, VaderCorpusError) as exc:
        parser.exit(1, "FALSUM PHASE5CA VADER INGESTION FAILED: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
