"""Phase 5CB: read-only VADER graded.xlsx cross-format integrity audit.

The workbook is a second immutable file in the same dataset revision, not an
independent dataset. This command authenticates it, compares it with the pinned
CSV and source metadata, and emits aggregate evidence only. It never trains or
runs a candidate model and never writes raw answers to disk.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
from io import BytesIO
import json
import math
from pathlib import Path, PurePosixPath
import posixpath
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import zipfile

from . import phase5ca_vader_corpus as ca

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = Path("data/phase5cb-vader-xlsx-protocol.json")
PROTOCOL_GIT_BLOB_SHA1 = "8f8153ffb3d2d77286cb95f97367ee18050c914c"
XLSX_MAX_BYTES = 2_000_000


def load_protocol(root: Path = ROOT) -> dict:
    raw = (root / PROTOCOL_PATH).read_bytes()
    ca.need(ca.git_blob_sha1(raw) == PROTOCOL_GIT_BLOB_SHA1,
            "Phase 5CB workbook/source-selection protocol changed after freeze")
    obj = ca.strict_json(raw)
    ca.need(isinstance(obj, dict)
            and obj.get("schema_version") == 1
            and obj.get("phase") == "5CB"
            and obj.get("status") == "VADER_GRADED_XLSX_CROSS_FORMAT_AUDIT_FROZEN_BEFORE_CANDIDATE_SCORING"
            and obj.get("freeze_base_commit") == "b83667f6e289514019ff2149452a2179030a27d5",
            "invalid Phase 5CB pre-inference protocol")
    ds = obj.get("dataset", {})
    ca.need(ds.get("repository") == "AfterQuery/vader"
            and ds.get("revision") == "9bef4b3b1994ce138d8a043b68ab0d8a81d8472d"
            and ds.get("license") == "CC-BY-4.0"
            and ds.get("workbook_path") == "graded.xlsx"
            and ds.get("workbook_sha256") == "9da644c6e9012fe124b95bd4460853ba045cafe78d26110e5cedde34dc20f158",
            "VADER workbook identity or license changed")
    ca.need(obj.get("reference_sources", {}).get("phase5ca_protocol_git_blob_sha1")
            == ca.PROTOCOL_GIT_BLOB_SHA1,
            "Phase 5CA source and split protocol changed")
    ca.need(obj.get("selection", {}).get("join_workbook_to_vader_csv_by_stable_ID_only") is True
            and obj.get("selection", {}).get("selection_does_not_use_human_scores_or_model_answers") is True
            and obj.get("selection", {}).get("no_row_repair_or_manual_selection") is True,
            "Phase 5CB stable-ID or score-blind selection rule weakened")
    ca.need(obj.get("private_material_boundary", {}).get("private_anjoman_source_overlap") == "UNKNOWN"
            and obj.get("private_material_boundary", {}).get("claim_fully_disjoint_from_private_anjoman_material") is False,
            "private Anjoman overlap must remain explicitly unknown")
    ca.need(obj.get("safety_and_claim_limits", {}).get("raw_third_party_answers_committed") is False
            and obj.get("safety_and_claim_limits", {}).get("model_inference_performed") is False
            and obj.get("safety_and_claim_limits", {}).get("official_submission") is False,
            "Phase 5CB safety boundary changed")
    return obj


def download_workbook(protocol: dict) -> tuple[bytes, dict]:
    ds = protocol["dataset"]
    revision = ds["revision"]
    path = ds["workbook_path"]
    ca.need(path == "graded.xlsx", "unapproved VADER workbook path")
    url = f"https://huggingface.co/datasets/AfterQuery/vader/resolve/{revision}/{path}?download=true"
    request = Request(url, headers={
        "Accept": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "User-Agent": "FALSUM-phase5cb-vader-xlsx-audit/1.0",
    })
    with urlopen(request, timeout=60) as response:
        ca.need(response.status == 200, "VADER workbook returned a non-200 status")
        final = urlparse(response.geturl())
        host = (final.hostname or "").lower()
        allowed_host = (
            host == "huggingface.co" or host.endswith(".huggingface.co")
            or host == "hf.co" or host.endswith(".hf.co")
        )
        ca.need(final.scheme == "https" and allowed_host,
                "VADER workbook redirected outside approved HTTPS hosts")
        raw = response.read(int(ds["workbook_max_bytes"]) + 1)
    ca.need(0 < len(raw) <= int(ds["workbook_max_bytes"]),
            "VADER workbook exceeded the frozen download byte cap")
    digest = ca.sha256(raw)
    ca.need(digest == ds["workbook_sha256"],
            "VADER workbook SHA-256 does not match the frozen Hugging Face file")
    return raw, {
        "path": path,
        "revision": revision,
        "bytes": len(raw),
        "sha256": digest,
        "xet_hash": ds["workbook_xet_hash"],
        "final_host": host,
    }


MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def _read_xml(archive: zipfile.ZipFile, path: str):
    raw = archive.read(path)
    upper = raw.upper()
    ca.need(b"<!DOCTYPE" not in upper and b"<!ENTITY" not in upper,
            "workbook XML DTD/entity declarations are not permitted")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ca.VaderCorpusError("workbook contains malformed XML: " + path) from exc


def _column_index(reference: str) -> int:
    match = re.fullmatch(r"([A-Z]+)[1-9][0-9]*", reference)
    ca.need(match is not None, "workbook contains an invalid cell reference")
    value = 0
    for char in match.group(1):
        value = value * 26 + ord(char) - 64
    return value - 1


def _shared_strings(archive: zipfile.ZipFile, names: set[str]) -> list[str]:
    path = "xl/sharedStrings.xml"
    if path not in names:
        return []
    root = _read_xml(archive, path)
    return [
        "".join(node.text or "" for node in item.iter(f"{{{MAIN_NS}}}t"))
        for item in root.findall(f"{{{MAIN_NS}}}si")
    ]


def _cell_value(cell, shared: list[str]) -> str:
    ca.need(cell.find(f"{{{MAIN_NS}}}f") is None,
            "formula cells are not permitted in the frozen source workbook")
    kind = cell.get("t")
    if kind == "inlineStr":
        inline = cell.find(f"{{{MAIN_NS}}}is")
        return "" if inline is None else "".join(
            node.text or "" for node in inline.iter(f"{{{MAIN_NS}}}t")
        )
    value_node = cell.find(f"{{{MAIN_NS}}}v")
    raw = "" if value_node is None or value_node.text is None else value_node.text
    if kind == "s":
        try:
            index = int(raw)
            return shared[index]
        except (ValueError, IndexError) as exc:
            raise ca.VaderCorpusError("invalid shared-string reference in workbook") from exc
    if kind == "b":
        ca.need(raw in ("0", "1"), "invalid boolean cell in workbook")
        return "TRUE" if raw == "1" else "FALSE"
    if kind == "e":
        raise ca.VaderCorpusError("Excel error cell is not a valid graded value")
    if kind in ("str", "d"):
        return raw
    ca.need(kind in (None, "n"), "unsupported workbook cell type: " + str(kind))
    if not raw:
        return ""
    try:
        number = Decimal(raw)
    except InvalidOperation:
        raise ca.VaderCorpusError("invalid numeric cell in workbook")
    ca.need(number.is_finite(), "non-finite numeric cell in workbook")
    if number == number.to_integral_value():
        return format(number.quantize(Decimal(1)), "f")
    return format(number.normalize(), "f")


def _read_sheet(archive: zipfile.ZipFile, path: str, shared: list[str]):
    root = _read_xml(archive, path)
    sheet_data = root.find(f"{{{MAIN_NS}}}sheetData")
    ca.need(sheet_data is not None, "worksheet has no sheetData")
    rows = []
    max_row = 0
    max_column = 0
    for row_node in sheet_data.findall(f"{{{MAIN_NS}}}row"):
        try:
            row_number = int(row_node.get("r", "0"))
        except ValueError as exc:
            raise ca.VaderCorpusError("worksheet row has an invalid index") from exc
        ca.need(row_number > 0, "worksheet row index must be positive")
        cells = {}
        for cell in row_node.findall(f"{{{MAIN_NS}}}c"):
            reference = cell.get("r", "")
            column = _column_index(reference)
            ca.need(column not in cells, "duplicate cell reference in worksheet row")
            cells[column] = _cell_value(cell, shared)
            max_column = max(max_column, column + 1)
        max_row = max(max_row, row_number)
        values = [cells.get(index, "") for index in range(max_column)]
        rows.append((row_number, values))
    return rows, max_row, max_column


def _trim(values: list[str]) -> list[str]:
    """Return a copy without trailing empty worksheet cells."""
    trimmed = list(values)
    while trimmed and trimmed[-1] == "":
        trimmed.pop()
    return trimmed


def parse_workbook(raw: bytes) -> tuple[list[dict[str, str]], dict]:
    ca.need(zipfile.is_zipfile(BytesIO(raw)), "graded.xlsx is not a valid ZIP workbook")
    try:
        archive = zipfile.ZipFile(BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ca.VaderCorpusError("graded.xlsx ZIP container is malformed") from exc
    with archive:
        infos = archive.infolist()
        names = {item.filename for item in infos}
        ca.need(len(infos) <= 5000, "workbook contains too many ZIP members")
        ca.need(sum(item.file_size for item in infos) <= 20_000_000,
                "workbook expanded size exceeds the frozen safety cap")
        ca.need(not any(
            name.startswith("/") or ".." in PurePosixPath(name).parts
            for name in names
        ), "workbook contains an unsafe ZIP member path")
        ca.need(not any("vbaproject.bin" in name.lower() for name in names),
                "macro-enabled content is not permitted")
        ca.need(not any(name.startswith("xl/externalLinks/") for name in names),
                "external workbook links are not permitted")
        workbook_root = _read_xml(archive, "xl/workbook.xml")
        rels_root = _read_xml(archive, "xl/_rels/workbook.xml.rels")
        relationships = {}
        for relation in rels_root.findall(f"{{{PKG_NS}}}Relationship"):
            ca.need(relation.get("TargetMode") != "External",
                    "external workbook relationships are not permitted")
            relationships[relation.get("Id")] = relation.get("Target", "")
        shared = _shared_strings(archive, names)
        sheets = []
        for sheet_node in workbook_root.findall(f".//{{{MAIN_NS}}}sheet"):
            sheet_name = sheet_node.get("name", "")
            relation_id = sheet_node.get(f"{{{REL_NS}}}id", "")
            target = relationships.get(relation_id, "")
            ca.need(bool(sheet_name) and bool(target),
                    "workbook sheet has no valid relationship target")
            if target.startswith("/"):
                sheet_path = target.lstrip("/")
            else:
                sheet_path = posixpath.normpath(posixpath.join("xl", target))
            ca.need(sheet_path.startswith("xl/")
                    and ".." not in PurePosixPath(sheet_path).parts
                    and sheet_path in names,
                    "workbook sheet target is outside the approved workbook tree")
            sheet_rows, max_row, max_column = _read_sheet(archive, sheet_path, shared)
            sheets.append((sheet_name, sheet_rows, max_row, max_column))
        matches = []
        for sheet_name, sheet_rows, max_row, max_column in sheets:
            for row_number, values in sheet_rows:
                if row_number > 10:
                    continue
                if tuple(_trim(list(values))) == ca.GRADED_FIELDS:
                    matches.append((sheet_name, sheet_rows, max_row, max_column, row_number))
        ca.need(len(matches) == 1,
                "workbook must contain exactly one worksheet with the frozen graded schema")
        sheet_name, sheet_rows, max_row, max_column, header_row = matches[0]
        rows: list[dict[str, str]] = []
        malformed = []
        duplicate_ids = []
        seen_ids = set()
        invalid_scores = []
        incomplete_answers = []
        physical_data_rows = 0
        for row_number, values in sheet_rows:
            if row_number <= header_row:
                continue
            normalized = list(values)
            if not any(normalized):
                continue
            physical_data_rows += 1
            extras = normalized[len(ca.GRADED_FIELDS):]
            if any(extras):
                malformed.append({"row": row_number, "reason": "nonempty_extra_columns"})
                continue
            normalized = normalized[:len(ca.GRADED_FIELDS)]
            normalized.extend([""] * (len(ca.GRADED_FIELDS) - len(normalized)))
            row = dict(zip(ca.GRADED_FIELDS, normalized))
            try:
                ident = ca._stable_id(row.get("ID", ""))
                ca._case_number(row.get("Case", ""))
                ca.canonical_repository(row.get("Repository", ""))
                ca._cwes(row.get("CWE", ""))
                ca._severity(row.get("Severity", ""), numeric_allowed=True)
                responses = {model: ca._model_response(row, model) for model in ca.MODELS}
            except (KeyError, ca.VaderCorpusError) as exc:
                reason = str(exc)[:160]
                malformed.append({"row": row_number, "reason": reason})
                if any(word in reason.lower() for word in ("score", "total", "explanation", "remediation", "other")):
                    invalid_scores.append(row.get("ID", "") or f"row:{row_number}")
                continue
            if ident in seen_ids:
                duplicate_ids.append(ident)
                continue
            seen_ids.add(ident)
            if not all(item["answer_present"] for item in responses.values()):
                incomplete_answers.append(ident)
            rows.append(row)
        return rows, {
            "sheet": sheet_name,
            "header_row": header_row,
            "worksheet_max_row": max_row,
            "worksheet_max_column": max_column,
            "data_rows": physical_data_rows,
            "valid_rows": len(rows),
            "malformed_rows": malformed,
            "malformed_row_count": len(malformed),
            "duplicate_stable_ids": duplicate_ids,
            "duplicate_stable_id_count": len(duplicate_ids),
            "incomplete_six_answer_ids": incomplete_answers,
            "incomplete_six_answer_count": len(incomplete_answers),
            "invalid_score_ids": invalid_scores,
            "invalid_score_count": len(invalid_scores),
        }


def _description(value: str) -> str:
    return "\n".join(line.rstrip() for line in value.splitlines()).strip()


def _row_digest(row: dict[str, str]) -> str:
    normalized = {}
    for field in ca.GRADED_FIELDS:
        value = row.get(field, "")
        if field.endswith(("-explanation", "-remediation", "-other", "-rating")):
            try:
                value = format(float(value), ".15g")
            except (TypeError, ValueError):
                value = str(value)
        else:
            value = str(value).replace("\r\n", "\n").replace("\r", "\n")
        normalized[field] = value
    return ca.sha256(ca.canonical_json(normalized))


def build_report(protocol: dict, workbook_rows: list[dict[str, str]],
                 workbook_diag: dict, vader_rows: list[dict[str, str]],
                 graded_csv_rows: list[dict[str, str]],
                 file_metadata: list[dict], csv_diagnostics: dict) -> tuple[dict, dict]:
    vader_by_id = {}
    for row in vader_rows:
        ident = ca._stable_id(row.get("ID", ""))
        ca.need(ident not in vader_by_id, "duplicate stable ID in authenticated vader.csv")
        vader_by_id[ident] = row
    workbook_by_id = {}
    for row in workbook_rows:
        ident = ca._stable_id(row.get("ID", ""))
        ca.need(ident not in workbook_by_id, "duplicate stable ID in graded.xlsx")
        workbook_by_id[ident] = row
    csv_by_id = {}
    for row in graded_csv_rows:
        ident = ca._stable_id(row.get("ID", ""))
        ca.need(ident not in csv_by_id, "duplicate stable ID in authenticated graded.csv")
        csv_by_id[ident] = row

    source_ids = set(vader_by_id)
    workbook_ids = set(workbook_by_id)
    csv_ids = set(csv_by_id)
    common_ids = sorted(source_ids & workbook_ids, key=int)
    source_only = sorted(source_ids - workbook_ids, key=int)
    workbook_only = sorted(workbook_ids - source_ids, key=int)
    csv_common = sorted(workbook_ids & csv_ids, key=int)
    workbook_only_vs_csv = sorted(workbook_ids - csv_ids, key=int)
    csv_only_vs_workbook = sorted(csv_ids - workbook_ids, key=int)
    known_public = set(protocol["known_public_falsum_source_inventory"]["repositories"])

    metadata_mismatches = []
    case_number_mismatches = []
    matched = []
    for ident in common_ids:
        source = vader_by_id[ident]
        graded = workbook_by_id[ident]
        try:
            source_repo = ca.canonical_repository(source["Repository"])
            graded_repo = ca.canonical_repository(graded["Repository"])
            source_cwe = ca._cwes(source["CWE"])
            graded_cwe = ca._cwes(graded["CWE"])
            source_severity = ca._severity(source["Severity"], numeric_allowed=False)
            graded_severity = ca._severity(graded["Severity"], numeric_allowed=True)
            source_description = _description(source["Description"])
            graded_description = _description(graded["Description"])
            source_case = ca._case_number(source["Case"])
            graded_case = ca._case_number(graded["Case"])
        except (KeyError, ca.VaderCorpusError) as exc:
            metadata_mismatches.append({"id": ident, "reason": str(exc)[:160]})
            continue
        if (source_repo != graded_repo or source_cwe != graded_cwe
                or source_severity != graded_severity
                or source_description != graded_description):
            metadata_mismatches.append({
                "id": ident,
                "repository_match": source_repo == graded_repo,
                "cwe_match": source_cwe == graded_cwe,
                "severity_match": source_severity == graded_severity,
                "description_match": source_description == graded_description,
            })
            continue
        if source_case != graded_case:
            case_number_mismatches.append(ident)
        matched.append({
            "id": ident,
            "case": source_case,
            "repository": source_repo,
            "repository_sha256": ca.sha256(source_repo.encode("utf-8")),
            "cwe": list(source_cwe),
            "severity": source_severity,
            "description_sha256": ca.sha256(source_description.encode("utf-8")),
            "reserved_holdout": (
                ca._holdout_bucket(source_repo) == 0 and source_repo not in known_public
            ),
        })

    holdout = [item for item in matched if item["reserved_holdout"]]
    holdout_repositories = sorted({item["repository"] for item in holdout})
    roster = [{
        "id": item["id"],
        "case": item["case"],
        "repository_sha256": item["repository_sha256"],
        "cwe": item["cwe"],
        "severity": item["severity"],
    } for item in holdout]
    matched_roster = [{
        "id": item["id"],
        "repository_sha256": item["repository_sha256"],
        "cwe": item["cwe"],
        "severity": item["severity"],
    } for item in matched]

    identical_csv_rows = sum(
        _row_digest(workbook_by_id[ident]) == _row_digest(csv_by_id[ident])
        for ident in csv_common
    )
    differing_csv_rows = len(csv_common) - identical_csv_rows
    readiness = protocol["readiness"]
    blockers = []
    if workbook_diag["data_rows"] != protocol["workbook_contract"]["expected_data_rows"]:
        blockers.append("workbook_data_row_count_differs_from_frozen_expectation")
    if workbook_diag["malformed_row_count"]:
        blockers.append("malformed_workbook_rows")
    if workbook_diag["duplicate_stable_id_count"]:
        blockers.append("duplicate_workbook_stable_IDs")
    if workbook_diag["invalid_score_count"]:
        blockers.append("invalid_workbook_score_rows")
    if workbook_diag["incomplete_six_answer_count"]:
        blockers.append("incomplete_six_model_answers")
    if metadata_mismatches:
        blockers.append("source_metadata_identity_mismatches")
    if workbook_only:
        blockers.append("workbook_IDs_missing_from_authenticated_source_metadata")
    if len(matched) < readiness["minimum_matched_cases"]:
        blockers.append("matched_case_count_below_frozen_minimum")
    if len(holdout) < readiness["minimum_holdout_cases"]:
        blockers.append("reserved_holdout_case_count_below_frozen_minimum")
    if len(holdout_repositories) < readiness["minimum_holdout_repositories"]:
        blockers.append("reserved_holdout_repository_count_below_frozen_minimum")
    if differing_csv_rows or workbook_only_vs_csv or csv_only_vs_workbook:
        blockers.append("xlsx_csv_cross_format_differences_require_source_owner_resolution")

    report = {
        "schema_version": 1,
        "status": "PHASE5CB_VADER_XLSX_CROSS_FORMAT_AUDIT_COMPLETE",
        "dataset": protocol["dataset"],
        "file_metadata": file_metadata,
        "source_counts": {
            "vader_csv_valid_rows": len(vader_rows),
            "graded_csv_valid_rows": len(graded_csv_rows),
            "graded_csv_malformed_rows": csv_diagnostics.get("graded_csv", {}).get("malformed_records", 0),
            "graded_xlsx_data_rows": workbook_diag["data_rows"],
            "graded_xlsx_valid_rows": len(workbook_rows),
        },
        "workbook": workbook_diag,
        "alignment": {
            "matched_workbook_source_IDs": len(matched),
            "source_only_IDs_excluded": len(source_only),
            "workbook_only_IDs": len(workbook_only),
            "source_metadata_mismatches": metadata_mismatches,
            "source_metadata_mismatch_count": len(metadata_mismatches),
            "case_number_mismatch_count": len(case_number_mismatches),
            "case_number_mismatches_reported_not_used_for_join": case_number_mismatches,
        },
        "csv_cross_format": {
            "common_stable_IDs": len(csv_common),
            "identical_rows": identical_csv_rows,
            "differing_rows": differing_csv_rows,
            "workbook_only_vs_valid_csv_IDs": len(workbook_only_vs_csv),
            "valid_csv_only_vs_workbook_IDs": len(csv_only_vs_workbook),
            "graded_csv_malformed_records_excluded": csv_diagnostics.get("graded_csv", {}).get("malformed_records", 0),
            "raw_answers_written_to_report": False,
        },
        "source_disjointness": {
            "reserved_holdout_cases": len(holdout),
            "reserved_holdout_repositories": len(holdout_repositories),
            "known_public_source_inventory_completeness": protocol["known_public_falsum_source_inventory"]["completeness"],
            "private_anjoman_source_overlap": "UNKNOWN",
            "fully_disjoint_from_private_anjoman_material": False,
            "fully_disjoint_from_model_pretraining": False,
        },
        "roster_sha256": ca.sha256(ca.canonical_json(roster)),
        "matched_case_roster_sha256": ca.sha256(ca.canonical_json(matched_roster)),
        "candidate_readiness": {
            "ready_for_candidate_scoring": not blockers,
            "reasons": blockers,
            "candidate_inference_performed": False,
            "candidate_training_performed": False,
        },
        "claim_limits": {
            "same_dataset_revision_not_independent_dataset": True,
            "workbook_not_treated_as_corrected_source_without_owner_confirmation": True,
            "derived_pairwise_preferences_not_original_pairwise_labels": True,
            "private_anjoman_overlap_unknown": True,
            "no_telegraph_network_improvement_claim": True,
            "no_network_eligible_material_claim": True,
            "raw_answers_written_to_report": False,
        },
    }
    roster_artifact = {
        "schema_version": 1,
        "status": "PHASE5CB_SCORE_BLIND_RESERVED_PUBLIC_SOURCE_HOLDOUT",
        "dataset_revision": protocol["dataset"]["revision"],
        "source_workbook_sha256": protocol["dataset"]["workbook_sha256"],
        "holdout_hash": protocol["selection"]["holdout_hash"],
        "case_count": len(roster),
        "repository_count": len(holdout_repositories),
        "roster_sha256": report["roster_sha256"],
        "cases": roster,
        "no_model_answers_or_human_scores": True,
        "private_anjoman_overlap": "UNKNOWN",
    }
    return report, roster_artifact


def run(root: Path = ROOT) -> tuple[dict, dict]:
    protocol = load_protocol(root)
    phase5ca_protocol = ca.load_protocol(root)
    source_files = phase5ca_protocol["source_files"]
    xlsx_raw, xlsx_meta = download_workbook(protocol)
    xlsx_rows, xlsx_diag = parse_workbook(xlsx_raw)
    vader_raw, vader_meta = ca._download(
        "vader.csv", source_files[0]["git_blob_sha1"],
        source_files[0]["max_bytes"], phase5ca_protocol["dataset"]["revision"],
    )
    graded_raw, graded_meta = ca._download(
        "graded.csv", source_files[1]["git_blob_sha1"],
        source_files[1]["max_bytes"], phase5ca_protocol["dataset"]["revision"],
    )
    vader_rows, vader_diag = ca._read_csv(vader_raw, ca.VADER_FIELDS, "vader.csv")
    graded_rows, graded_diag = ca._read_csv(graded_raw, ca.GRADED_FIELDS, "graded.csv")
    report, roster = build_report(
        protocol, xlsx_rows, xlsx_diag, vader_rows, graded_rows,
        [xlsx_meta, vader_meta, graded_meta],
        {"vader_csv": vader_diag, "graded_csv": graded_diag},
    )
    return report, roster


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--roster", type=Path, required=True)
    args = parser.parse_args()
    report, roster = run()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.roster.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(ca.canonical_json(report))
    args.roster.write_bytes(ca.canonical_json(roster))
    print(json.dumps({
        "status": report["status"],
        "candidate_ready": report["candidate_readiness"]["ready_for_candidate_scoring"],
        "reasons": report["candidate_readiness"]["reasons"],
        "matched": report["alignment"]["matched_workbook_source_IDs"],
        "holdout_cases": report["source_disjointness"]["reserved_holdout_cases"],
        "holdout_repositories": report["source_disjointness"]["reserved_holdout_repositories"],
        "xlsx_csv_differing_rows": report["csv_cross_format"]["differing_rows"],
        "xlsx_csv_workbook_only": report["csv_cross_format"]["workbook_only_vs_valid_csv_IDs"],
        "xlsx_csv_csv_only": report["csv_cross_format"]["valid_csv_only_vs_workbook_IDs"],
    }, sort_keys=True))
    if not report["candidate_readiness"]["ready_for_candidate_scoring"]:
        print("::warning::VADER workbook is authenticated but remains blocked; no candidate inference was run.")


if __name__ == "__main__":
    main()
