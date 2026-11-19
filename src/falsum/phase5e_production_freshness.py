"""Validate actual public FALSUM five-source evidence, not merely old model pages.

The only live green outcome requires exact equality between a fresh offline
five-case source-authenticated build and public HTTPS production JSON. This is
a deployment/content check, NOT model accuracy, expert gold or H2 acceptance.
Offline fixtures never report successful *live* verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

from .phase4v_real_source_witness_site import assemble

STATUS_LIVE = "PHASE5E_LIVE_PRODUCTION_FIVE_SOURCE_WITNESS_EXACTLY_MATCHES_REPRODUCIBLE_BUILD"
STATUS_OFFLINE = "PHASE5E_OFFLINE_CONTENT_FIXTURE_ONLY_NOT_PUBLIC_PRODUCTION"
HOST = "falsum-evidence-lab.vercel.app"
BASE = "https://" + HOST
JSON_NAME = "FIVE-AUTHENTIC-UPSTREAM-SOURCE-REGRESSIONS.json"
MAX_JSON = 240_000
MAX_HTML = 330_000


class FreshnessError(ValueError):
    """Source authenticity, endpoint, or deployment freshness failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FreshnessError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compare(expected: dict, raw_json: bytes, raw_html: bytes, *, live: bool) -> dict:
    """Check all published bytes against the local real source-evidence build."""
    require(type(live) is bool, "untrusted origin status")
    require(isinstance(raw_json, bytes) and 0 < len(raw_json) <= MAX_JSON,
            "missing or oversized public witness JSON")
    require(isinstance(raw_html, bytes) and 0 < len(raw_html) <= MAX_HTML,
            "missing or oversized public witness page")
    try:
        actual = json.loads(raw_json)
        html = raw_html.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise FreshnessError("invalid public witness JSON/HTML") from exc
    require(isinstance(expected, dict) and isinstance(actual, dict),
            "unexpected source proof types")
    require(expected.get("status") ==
            "PHASE5D_STATIC_FIVE_REAL_SOURCE_EXECUTIONS_PRECOMPUTED_CLAIMS_NOT_MODEL_ACCURACY"
            and expected.get("source_fix_stage_count") == 5
            and expected.get("upstream_project_count") == 4
            and expected.get("precomputed_python_evaluations") == 80
            and expected.get("by_construction_verdict_counts") == {
                "SUPPORTED": 10, "CONTRADICTED": 10, "ABSTAIN": 60
            }
            and expected.get("independent_appsec_expert_gold_labels") == 0
            and expected.get("network_evaluator_registered") is False
            and expected.get("trained_model_improvement_proven") is False
            and expected.get("official_h2_submission_confirmed") is False,
            "local build is not authenticated five-stage source-only evidence")
    require(actual == expected,
            "public production evidence is STALE or does not exactly match locally authenticated five-case build")
    require(html.count('id="witness-data"') == 1 and
            "PHASE5D_STATIC_FIVE_REAL_SOURCE_EXECUTIONS" in html
            and "FIVE-AUTHENTIC-UPSTREAM-SOURCE-REGRESSIONS.json" in html
            and "FIVE PINNED PATCH STAGES" in html
            and "Flask" not in ("this field must not be a guard",)
            and "__FALSUM_REAL_WITNESS_DATA__" not in html,
            "production HTML is stale or contains an unpopulated witness app")
    cases = actual.get("cases")
    require(isinstance(cases, list)
            and [x["id"] for x in cases] == [
                "koa-redirect", "hono-csrf", "langchain-path",
                "langchain-symlink", "flask-session-cookie-vary",
            ]
            and all(isinstance(x.get("decisions"), dict) and len(x["decisions"]) == 16 for x in cases)
            and cases[-1].get("actions_run_url") ==
            "https://github.com/Iniwura/falsum/actions/runs/44524997174",
            "wrong public upstream project ordering or archived Flask Actions proof")
    return {
        "schema_version": 1,
        "status": STATUS_LIVE if live else STATUS_OFFLINE,
        "input_provenance": "PUBLIC_HTTPS_VERCEL_ALIAS" if live else "OFFLINE_UNTRUSTED_FIXTURE",
        "production_alias": BASE if live else None,
        "actual_production_content_verified": live,
        "local_authenticated_source_report_sha256": digest(canonical(expected)),
        "served_source_report_sha256": digest(canonical(actual)),
        "served_page_sha256": digest(raw_html),
        "original_source_fix_stages": 5,
        "distinct_source_repositories": 4,
        "constructed_source_checks": 80,
        "by_construction_verdict_counts": expected["by_construction_verdict_counts"],
        "fifth_case": "flask-session-cookie-vary",
        "original_fifth_case_actions_run": cases[-1]["actions_run_url"],
        "trained_model_generalization_measured": False,
        "independent_human_appsec_gold_labels": 0,
        "registered_telegraph_scorer": False,
        "official_h2_entry_submitted": False,
        "warning": (
            "This checks public deployment freshness and exact historical "
            "source-test content. It is NOT ML accuracy, external human gold, "
            "production exploit confirmation, or Telegraph H2 submission."
        ),
    }


def _read_public(path: str, max_bytes: int) -> bytes:
    require(path in ("/witness/" + JSON_NAME, "/witness/"),
            "public fetch is limited to exact known workbench paths")
    url = BASE + path
    request = urllib.request.Request(url, headers={
        "User-Agent": "FALSUM-public-release-freshness/1.0",
        "Accept": "application/json" if path.endswith(".json") else "text/html",
    })
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            redirect = urllib.parse.urlsplit(response.geturl())
            require(redirect.scheme == "https" and redirect.netloc == HOST
                    and redirect.path.rstrip("/") == path.rstrip("/"),
                    "public production request redirected away from expected endpoint")
            require(response.status == 200, "public production page not successful")
            raw = response.read(max_bytes + 1)
    except (OSError, ValueError) as exc:
        raise FreshnessError("public production source path was not fetchable: " + str(exc)) from exc
    require(0 < len(raw) <= max_bytes, "live witness response missing or oversized")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare real Vercel witness against latest authenticated source build")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--offline-json", type=Path,
                        help="only a local test fixture; cannot attest to public production")
    parser.add_argument("--offline-html", type=Path,
                        help="only a local test fixture; cannot attest to public production")
    args = parser.parse_args(argv)
    try:
        require((args.offline_json is None) == (args.offline_html is None),
                "both offline fixture inputs required together")
        inputs = {x.resolve() for x in (args.offline_json, args.offline_html)
                  if x is not None}
        require(not args.out.exists() and not args.out.is_symlink()
                and args.out.resolve() not in inputs,
                "refuse overwrite of existing output or source fixture")
        expected = assemble(args.root)
        if args.offline_json is not None:
            raw_json = args.offline_json.read_bytes()
            raw_html = args.offline_html.read_bytes()
            is_live = False
        else:
            raw_json = _read_public("/witness/" + JSON_NAME, MAX_JSON)
            raw_html = _read_public("/witness/", MAX_HTML)
            is_live = True
        report = compare(expected, raw_json, raw_html, live=is_live)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
        print(json.dumps({
            "status": report["status"],
            "verified_live": report["actual_production_content_verified"],
            "cases": 5, "source_checks": 80,
            "model_accuracy_claimed": False,
        }, sort_keys=True))
        return 0
    except (OSError, TypeError, UnicodeError, KeyError, ValueError) as exc:
        parser.exit(1, "FALSUM PUBLIC RELEASE FRESHNESS NOT VERIFIED: " + str(exc)[:250] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
