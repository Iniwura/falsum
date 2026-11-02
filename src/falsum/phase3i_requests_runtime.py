"""Phase 3I: observe real Requests proxy authorization handling before/after 2023 fix.

Exactly requests==2.30.0 / 2.31.0. Only in-memory PreparedRequest
objects and an explicitly fake proxy address are used. No HTTP transport,
socket, real credentials, user applications or dynamic untrusted inputs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path

from .real_fix_corpus import load_queue

STATUS = "PHASE3I_INSTALLED_REQUESTS_REDIRECT_PROXY_HEADER_OBSERVATION_NOT_MODEL_EVALUATION"
CASE = "real-requests-proxy-auth"
REPOSITORY = "psf/requests"
FIX_COMMIT = "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"
SOURCE_BLOB = "dbcf2a7b0ee2898b72714b756e4b27fbbad4beab"
TEST_BLOB = "b420c44d73cde0c2ab7e7aa0e5182b345436f718"
ADVISORY = "GHSA-j8r2-6x86-q33q"
CVE = "CVE-2023-32681"
VERSIONS = ("2.30.0", "2.31.0")
FAKE_PROXY = "http://falsum-test:never-a-secret@proxy.invalid:8080"
PLAIN_PROXY = "http://proxy.invalid:8080"
FAKE_CREDENTIALS = "falsum-test:never-a-secret"
SCENARIOS = (
    ("credentialed_https", "https", "credentialed", False),
    ("credentialed_http", "http", "credentialed", False),
    ("anonymous_https", "https", "anonymous", False),
    ("without_proxy_https", "https", "none", False),
    ("stale_header_without_proxy_https", "https", "none", True),
)
EXPECTED = {
    "2.30.0": (True, True, False, False, False),
    "2.31.0": (False, True, False, False, False),
}


class BoundaryError(ValueError):
    """An unsupported runtime or unverified finding is rejected."""


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def pin_queue(path: Path) -> dict:
    queue = load_queue(path)
    if len(queue["cases"]) != 4:
        raise BoundaryError("expected original four-source pinned queue")
    matches = [r for r in queue["cases"] if r["id"] == CASE]
    if len(matches) != 1:
        raise BoundaryError("original Requests source identity unavailable")
    row = matches[0]
    for name, value in {
        "repository": REPOSITORY, "commit": FIX_COMMIT,
        "source_blob": SOURCE_BLOB, "test_blob": TEST_BLOB,
        "source_path": "requests/sessions.py", "test_path": "tests/test_requests.py",
        "advisory": ADVISORY, "cve": CVE,
    }.items():
        if row.get(name) != value:
            raise BoundaryError("original upstream source/test identity drift: " + name)
    return row


def validate_report(report: dict) -> None:
    if not isinstance(report, dict):
        raise BoundaryError("report must be a JSON object")
    required = {
        "schema_version", "status", "intent", "case_id", "advisory", "cve",
        "pinned_upstream_fix_commit", "pinned_source_blob_sha1", "pinned_regression_test_blob_sha1",
        "actual_requests_version", "actual_installed_source_sha256", "source_file_outside_repo",
        "actual_library_method_executed", "version_appropriate_fix_condition_present",
        "no_socket_or_http_transport", "only_synthetic_proxy_auth", "real_credentials_used",
        "real_application_executed", "trust_environment_disabled", "observations",
        "model_scored", "independently_approved_labels", "accepted_training_pairs",
        "accepted_anjoman_rows", "network_eligible", "evaluator_registered",
    }
    if set(report) != required:
        raise BoundaryError("missing or extra evidence report fields")
    version = report.get("actual_requests_version")
    if (type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["status"] != STATUS or report["intent"] != "SECURITY_REVIEW_GENERAL"
            or report["case_id"] != CASE or report["advisory"] != ADVISORY
            or report["cve"] != CVE or version not in VERSIONS
            or report["pinned_upstream_fix_commit"] != FIX_COMMIT
            or report["pinned_source_blob_sha1"] != SOURCE_BLOB
            or report["pinned_regression_test_blob_sha1"] != TEST_BLOB
            or report["source_file_outside_repo"] is not True
            or report["actual_library_method_executed"] is not True
            or report["version_appropriate_fix_condition_present"] is not True
            or report["no_socket_or_http_transport"] is not True
            or report["only_synthetic_proxy_auth"] is not True
            or report["real_credentials_used"] != 0
            or report["real_application_executed"] is not False
            or report["trust_environment_disabled"] is not True
            or report["model_scored"] is not False
            or report["independently_approved_labels"] != 0
            or report["accepted_training_pairs"] != 0
            or report["accepted_anjoman_rows"] != 0
            or report["network_eligible"] is not False
            or report["evaluator_registered"] is not False):
        raise BoundaryError("fabricated, unpinned or falsely promoted security evidence")
    digest = report.get("actual_installed_source_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise BoundaryError("installed library source fingerprint is invalid")
    rows = report.get("observations")
    if not isinstance(rows, list) or len(rows) != len(SCENARIOS):
        raise BoundaryError("missing actual control observations")
    for i, (case_name, scheme, proxy_kind, stale) in enumerate(SCENARIOS):
        item = rows[i]
        if (not isinstance(item, dict) or set(item) != {
            "case", "url_scheme", "proxy_kind", "preexisting_fake_auth_header",
            "proxy_authorization_header_after_rebuild",
            "observed_header_matches_fake_proxy_credentials",
            "returned_proxy_configuration_preserved",
        } or item.get("case") != case_name or item.get("url_scheme") != scheme
                or item.get("proxy_kind") != proxy_kind
                or item.get("preexisting_fake_auth_header") is not stale
                or item.get("proxy_authorization_header_after_rebuild") is not EXPECTED[version][i]
                or item.get("observed_header_matches_fake_proxy_credentials") is not EXPECTED[version][i]
                or item.get("returned_proxy_configuration_preserved") is not True):
            raise BoundaryError("runtime/control observation differs from historical source preconditions")


def run(version: str, source_queue: Path, repository_root: Path) -> dict:
    if version not in VERSIONS:
        raise BoundaryError("not one of the two explicitly allowed historical releases")
    pin_queue(source_queue)
    import requests
    import requests.sessions
    installed = importlib.metadata.version("requests")
    if installed != version or requests.__version__ != version:
        raise BoundaryError("real installed Requests version does not match exact historical pin")
    source_path = Path(inspect.getfile(requests.sessions.SessionRedirectMixin)).resolve(strict=True)
    if source_path.is_relative_to(repository_root.resolve()) or not source_path.is_file():
        raise BoundaryError("Requests implementation must come from installed distribution")
    method = inspect.getsource(requests.sessions.SessionRedirectMixin.rebuild_proxies)
    fix_line = "if not scheme.startswith('https') and username and password:"
    # Both exact release sources were checked against the pinned upstream patch.
    if (fix_line in method) is not (version == "2.31.0"):
        raise BoundaryError("installed Requests function differs from known historic fix")
    observed = []
    for case_name, scheme, proxy_kind, stale in SCENARIOS:
        proxy = FAKE_PROXY if proxy_kind == "credentialed" else PLAIN_PROXY
        proxies = {} if proxy_kind == "none" else {scheme: proxy}
        with requests.Session() as session:
            session.trust_env = False
            prepared = session.prepare_request(requests.Request(
                "GET", scheme + "://falsum.example.invalid/harmless-local-check"
            ))
            if stale:
                prepared.headers["Proxy-Authorization"] = "Fake-Old-Header"
            # Actual installed Requests method, not a reimplementation. No send() call.
            returned = session.rebuild_proxies(prepared, proxies)
            auth = prepared.headers.get("Proxy-Authorization")
            if auth is None:
                verified_demo_header = False
            else:
                if not auth.startswith("Basic "):
                    raise BoundaryError("unexpected authorization mechanism")
                try:
                    decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
                except (ValueError, UnicodeDecodeError) as exc:
                    raise BoundaryError("unexpected encoded auth header") from exc
                if decoded != FAKE_CREDENTIALS:
                    raise BoundaryError("runtime produced non-synthetic proxy credentials")
                verified_demo_header = True
            observed.append({
                "case": case_name, "url_scheme": scheme, "proxy_kind": proxy_kind,
                "preexisting_fake_auth_header": stale,
                "proxy_authorization_header_after_rebuild": auth is not None,
                "observed_header_matches_fake_proxy_credentials": verified_demo_header,
                "returned_proxy_configuration_preserved": returned == proxies,
            })
    report = {
        "schema_version": 1, "status": STATUS, "intent": "SECURITY_REVIEW_GENERAL",
        "case_id": CASE, "advisory": ADVISORY, "cve": CVE,
        "pinned_upstream_fix_commit": FIX_COMMIT,
        "pinned_source_blob_sha1": SOURCE_BLOB, "pinned_regression_test_blob_sha1": TEST_BLOB,
        "actual_requests_version": version,
        "actual_installed_source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "source_file_outside_repo": True, "actual_library_method_executed": True,
        "version_appropriate_fix_condition_present": True,
        "no_socket_or_http_transport": True, "only_synthetic_proxy_auth": True,
        "real_credentials_used": 0, "real_application_executed": False,
        "trust_environment_disabled": True, "observations": observed,
        "model_scored": False, "independently_approved_labels": 0,
        "accepted_training_pairs": 0, "accepted_anjoman_rows": 0,
        "network_eligible": False, "evaluator_registered": False,
    }
    validate_report(report)
    return report


def compare(before: dict, after: dict) -> dict:
    validate_report(before)
    validate_report(after)
    if before["actual_requests_version"] != "2.30.0" or after["actual_requests_version"] != "2.31.0":
        raise BoundaryError("invalid before/after version pairing")
    if before["actual_installed_source_sha256"] == after["actual_installed_source_sha256"]:
        raise BoundaryError("same installed library source for both reported versions")
    changed = [
        b["case"] for b, a in zip(before["observations"], after["observations"])
        if b["proxy_authorization_header_after_rebuild"] != a["proxy_authorization_header_after_rebuild"]
    ]
    if changed != ["credentialed_https"]:
        raise BoundaryError("wrong changed security boundary or failed controls")
    return {
        "schema_version": 1,
        "status": "PHASE3I_HISTORICAL_REQUESTS_PROXY_AUTH_BOUNDARY_OBSERVED_TWO_REAL_INSTALLS",
        "intent": "SECURITY_REVIEW_GENERAL",
        "case_id": CASE, "advisory": ADVISORY, "cve": CVE,
        "affected_version": "2.30.0", "fixed_version": "2.31.0",
        "upstream_fix_commit": FIX_COMMIT,
        "controls_per_version": len(SCENARIOS),
        "historical_https_proxy_header_before": True,
        "https_proxy_header_after_fix": False,
        "stable_http_credentialed_proxy_header": True,
        "stable_other_negative_controls": 3,
        "outbound_network_calls": 0, "external_apps_tested": 0,
        "model_scored": False, "independently_approved_labels": 0,
        "accepted_anjoman_rows": 0, "registered_evaluator": False,
        "network_eligible": False,
        "notice": "A real in-memory Requests redirect-proxy header reconstruction difference. No actual redirect or external network call; this is not a live credential leak, model score, independent review or eligible network material.",
    }


def write_new(path: Path, doc: dict) -> None:
    if path.exists():
        raise BoundaryError("refuse to overwrite prior evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(doc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observe two exact Requests library versions offline")
    cmds = parser.add_subparsers(dest="command", required=True)
    one = cmds.add_parser("run")
    one.add_argument("--version", choices=VERSIONS, required=True)
    one.add_argument("--queue", type=Path, required=True)
    one.add_argument("--repo-root", type=Path, required=True)
    one.add_argument("--out", type=Path, required=True)
    both = cmds.add_parser("compare")
    both.add_argument("--before", type=Path, required=True)
    both.add_argument("--after", type=Path, required=True)
    both.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = run(args.version, args.queue, args.repo_root)
        else:
            result = compare(json.loads(args.before.read_text()), json.loads(args.after.read_text()))
        write_new(args.out, result)
        print(json.dumps({
            "status": result["status"], "requests_version": result.get("actual_requests_version"),
            "model_scored": False, "network_eligible": False,
        }, indent=2))
        return 0
    except (BoundaryError, ValueError, TypeError, KeyError, OSError) as exc:
        parser.exit(1, f"FALSUM PHASE 3I REAL REQUESTS RUNTIME GATE: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
