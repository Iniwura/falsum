"""Command line entry point for evidence dataset quality checks and exports."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ledger import LedgerError, export_jsonl, load_ledger
from .scenarios import ScenarioError, read_casebook, readiness_report, export_reviewed, verify_source_snapshots
from .osv import SourceError, audit_ledger_snapshots, verify_snapshot, version_status
from .sources import fetch_osv
from .preflight import preflight_casebook, PreflightError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="falsum")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="check ledger without publishing anything")
    validate.add_argument("ledger", type=Path)
    export = commands.add_parser("export", help="export reviewed pairs for a specified split")
    export.add_argument("ledger", type=Path)
    export.add_argument("--split", choices=("train", "validation", "holdout"), required=True)
    export.add_argument("--out", type=Path, required=True)
    acquire = commands.add_parser("fetch-osv", help="pin a public OSV advisory to an immutable local snapshot")
    acquire.add_argument("advisory_id", help="CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx")
    acquire.add_argument("--directory", type=Path, required=True)
    check = commands.add_parser("check-osv", help="verify a pinned snapshot and report a conservative version status")
    check.add_argument("snapshot", type=Path)
    check.add_argument("--advisory", required=True)
    check.add_argument("--ecosystem", required=True)
    check.add_argument("--package", required=True)
    check.add_argument("--version", required=True)
    check.add_argument("--expect", choices=("affected", "unaffected"))
    audit = commands.add_parser("audit-snapshots", help="verify reviewed evidence rows against archived OSV records")
    audit.add_argument("ledger", type=Path)
    audit.add_argument("--directory", type=Path, required=True)
    audit.add_argument("--include-drafts", action="store_true", help="source-audit draft records without marking them reviewed")
    guidance_audit = commands.add_parser('audit-scenarios', help='verify pinned security guidance snapshots')
    guidance_audit.add_argument('casebook', type=Path)
    casebook = commands.add_parser("check-scenarios", help="validate security-review draft scenarios")
    casebook.add_argument("casebook", type=Path)
    case_export = commands.add_parser("export-scenarios", help="export only fully reviewed scenario pairs")
    case_export.add_argument("casebook", type=Path)
    case_export.add_argument("--split", required=True, choices=("train", "validation", "holdout"))
    case_export.add_argument("--out", required=True, type=Path)
    preflight = commands.add_parser("preflight", help="diagnose draft corpus against V2 dataset thresholds; NEVER eligible")
    preflight.add_argument("casebook", type=Path)
    preflight.add_argument("--diagnostic-dir", type=Path)
    source_witness = commands.add_parser(
        "verify-source-review",
        help="check structured review claims against four real upstream code regression witnesses; NOT a trained adapter",
    )
    source_witness.add_argument("--index", type=Path, required=True,
                                help="permanent public four-stage GitHub Actions witness-hash index")
    source_witness.add_argument("--source-lock", type=Path, required=True,
                                help="Phase 4P pinned Git source/test selection")
    source_witness.add_argument("--requests", type=Path,
                                help="typed review claim JSON; omitted means 32 by-construction safety tests")
    source_witness.add_argument("--out", type=Path, required=True,
                                help="new write-once public-safe source-review report")
    source_witness.add_argument("--flask-lock", type=Path,
                                help="optional immutable Flask source/test selection for fifth historical witness")
    source_witness.add_argument("--flask-proof-b64", type=Path,
                                help="optional original GitHub Actions Flask ZIP in pinned portable base64 form")
    scorecard = commands.add_parser(
        "score-source-predictions",
        help="export or score open-book 80-item upstream security-review predictions, NOT expert gold",
    )
    scorecard.add_argument("mode", choices=("export", "score", "baseline"))
    scorecard.add_argument("--challenge-out", type=Path)
    scorecard.add_argument("--template-out", type=Path)
    scorecard.add_argument("--predictions", type=Path)
    scorecard.add_argument("--strategy",
                           choices=("always-abstain", "always-supported", "always-contradicted"))
    scorecard.add_argument("--out", type=Path)
    balanced = commands.add_parser(
        "score-source-balanced",
        help="audit the 80-item metadata leak, export or score 30 balanced source-role-neutral questions (NOT blind gold)",
    )
    balanced.add_argument("mode", choices=("audit", "export", "baseline", "score"))
    balanced.add_argument("--out", type=Path)
    balanced.add_argument("--questions-out", type=Path)
    balanced.add_argument("--template-out", type=Path)
    balanced.add_argument("--predictions", type=Path)
    balanced.add_argument("--strategy",
                          choices=("always-abstain", "always-supported",
                                   "always-contradicted", "slot-a-is-parent"))
    disjoint = commands.add_parser(
        "score-new-source-projects",
        help="4 previously untested original public Git projects, 8 code revisions, 8 upstream test blobs, 24 counterbalanced tasks; no expert gold",
    )
    disjoint.add_argument("mode",choices=("export","score","baseline"))
    disjoint.add_argument("--questions-out",type=Path)
    disjoint.add_argument("--template-out",type=Path)
    disjoint.add_argument("--source-proof-out",type=Path)
    disjoint.add_argument("--questions",type=Path)
    disjoint.add_argument("--predictions",type=Path)
    disjoint.add_argument("--out",type=Path)
    safe_ref = commands.add_parser(
        "filter-security-references",
        help="use original independently reviewed GHSA version intervals to suppress inapplicable external references; display-only, not a registered scorer",
    )
    safe_ref.add_argument("--out",required=True,type=Path)
    safe_ref.add_argument("--role",choices=(
        "canonical_routed_off_target","direct_deps_dev_ghsa",
        "direct_deps_dev_version"))
    safe_ref.add_argument("--request-json",type=Path)
    safe_ref.add_argument("--response-json",type=Path)
    version_quality = commands.add_parser(
        "audit-reviewed-advisory-version",
        help="six original Git-reviewed advisory source files vs two real published Miner outputs; exact target version only, NOT ranking",
    )
    version_quality.add_argument("--out",type=Path,required=True)
    consume = commands.add_parser(
        "audit-telegraph-consumption",
        help="strict original source-bound application allow/deny policy; two authentic real paid captures and 24 constructed tests, not network scoring",
    )
    consume.add_argument("--out",type=Path,required=True)
    consume.add_argument("--request-json",type=Path)
    consume.add_argument("--response-json",type=Path)
    paired = commands.add_parser(
        "audit-telegraph-consistency",
        help="source-pinned original two-task paid Telegraph response-identity contrast; not model quality gold",
    )
    paired.add_argument("--out",type=Path,required=True)
    telegraph = commands.add_parser(
        "audit-telegraph-target",
        help="source-pinned real paid SECURITY_REVIEW_GENERAL response relevance audit; not a registered scorer",
    )
    telegraph.add_argument("--out",type=Path,required=True)
    telegraph.add_argument("--request-json",type=Path)
    telegraph.add_argument("--response-json",type=Path)
    counterbalanced = commands.add_parser(
        "score-counterbalanced-source",
        help="24 authenticated raw-source / swapped-option tasks, four-way reversal scoring and actual model inference; NOT blind gold",
    )
    counterbalanced.add_argument("mode",choices=("export","score","baseline","infer","audit"))
    counterbalanced.add_argument("--questions-out",type=Path)
    counterbalanced.add_argument("--template-out",type=Path)
    counterbalanced.add_argument("--questions",type=Path)
    counterbalanced.add_argument("--predictions",type=Path)
    counterbalanced.add_argument("--raw",type=Path)
    counterbalanced.add_argument("--model",choices=("small","larger"))
    counterbalanced.add_argument("--out",type=Path)
    raw_code = commands.add_parser(
        "score-raw-code",
        help="authenticated real Git source excerpts, model inference or unverified developer score; not independent gold",
    )
    raw_code.add_argument("mode", choices=("export","score","infer","audit"))
    raw_code.add_argument("--questions-out", type=Path)
    raw_code.add_argument("--template-out", type=Path)
    raw_code.add_argument("--questions", type=Path)
    raw_code.add_argument("--predictions", type=Path)
    raw_code.add_argument("--raw", type=Path)
    raw_code.add_argument("--out", type=Path)
    source_pair = commands.add_parser(
        "score-source-context",
        help="export or score three public original upstream source-context predictions; no live model or expert gold",
    )
    source_pair.add_argument("mode", choices=("export", "score", "baseline"))
    source_pair.add_argument("--questions-out", type=Path)
    source_pair.add_argument("--template-out", type=Path)
    source_pair.add_argument("--predictions", type=Path)
    source_pair.add_argument("--strategy",
                             choices=("always-A", "always-B", "always-ABSTAIN"))
    source_pair.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "score-new-source-projects":
            from .phase5u_project_disjoint_security import main as new_sources_main
            if args.mode=="export":
                if (args.questions_out is None or args.template_out is None
                        or args.source_proof_out is None):
                    parser.error("export requires --questions-out --template-out --source-proof-out")
                return new_sources_main(["export",
                    "--questions-out",str(args.questions_out),
                    "--template-out",str(args.template_out),
                    "--source-proof-out",str(args.source_proof_out)])
            if args.out is None:
                parser.error("score/baseline requires --out")
            cmd=[args.mode,"--out",str(args.out)]
            if args.mode=="score":
                if args.questions is None or args.predictions is None:
                    parser.error("score requires --questions --predictions")
                cmd+=["--questions",str(args.questions),
                      "--predictions",str(args.predictions)]
            return new_sources_main(cmd)
        if args.command == "filter-security-references":
            from .phase5z_reviewed_advisory_consumption import main as safe_ref_main
            cmd=["--out",str(args.out)]
            for key,flag in (
                ("role","--role"),
                ("request_json","--request-json"),
                ("response_json","--response-json")
            ):
                val=getattr(args,key)
                if val is not None:
                    cmd.extend((flag,str(val)))
            return safe_ref_main(cmd)
        if args.command == "audit-reviewed-advisory-version":
            from .phase5y_original_reviewed_version_applicability import main as verified_version_main
            return verified_version_main(["--out",str(args.out)])
        if args.command == "audit-telegraph-consumption":
            from .phase5t_application_consumption import main as consume_main
            cmd=["--out",str(args.out)]
            if args.request_json is not None:
                cmd+=["--request-json",str(args.request_json)]
            if args.response_json is not None:
                cmd+=["--response-json",str(args.response_json)]
            return consume_main(cmd)
        if args.command == "audit-telegraph-consistency":
            from .phase5r_telegraph_two_task_consistency import main as paired_main
            return paired_main(["--out",str(args.out)])
        if args.command == "audit-telegraph-target":
            from .phase5q_telegraph_target_gate import main as telegraph_main
            a=["--out",str(args.out)]
            if args.request_json is not None:
                a+=["--request-json",str(args.request_json)]
            if args.response_json is not None:
                a+=["--response-json",str(args.response_json)]
            return telegraph_main(a)
        if args.command == "score-counterbalanced-source":
            from .phase5s_counterbalanced_source_invariance import main as counterbalanced_main
            if args.mode=="export":
                if args.questions_out is None or args.template_out is None:
                    parser.error("export requires --questions-out and --template-out")
                return counterbalanced_main([
                    "export","--questions-out",str(args.questions_out),
                    "--template-out",str(args.template_out),
                ])
            if args.out is None:
                parser.error("all scoring/inference modes require --out")
            if args.mode=="baseline":
                return counterbalanced_main(["baseline","--out",str(args.out)])
            if args.questions is None:
                parser.error("score/infer/audit need --questions")
            argv=[args.mode,"--questions",str(args.questions),"--out",str(args.out)]
            if args.mode=="score":
                if args.predictions is None:
                    parser.error("score needs --predictions")
                argv+=["--predictions",str(args.predictions)]
            else:
                if args.model is None:
                    parser.error("infer/audit need --model small or larger")
                argv+=["--model",args.model]
                if args.mode=="audit":
                    if args.raw is None:
                        parser.error("audit needs --raw")
                    argv+=["--raw",str(args.raw)]
            return counterbalanced_main(argv)
        if args.command == "score-raw-code":
            from .phase5p_raw_code_evaluator import main as raw_code_main
            if args.mode == "export":
                if args.questions_out is None or args.template_out is None:
                    parser.error("export needs --questions-out and --template-out")
                return raw_code_main(["export","--questions-out",str(args.questions_out),
                                      "--template-out",str(args.template_out)])
            if args.questions is None or args.out is None:
                parser.error("score/infer/audit require --questions and --out")
            cmd=[args.mode,"--questions",str(args.questions),"--out",str(args.out)]
            if args.mode == "score":
                if args.predictions is None:
                    parser.error("score needs --predictions")
                cmd.extend(("--predictions",str(args.predictions)))
            if args.mode == "audit":
                if args.raw is None:
                    parser.error("audit needs --raw")
                cmd.extend(("--raw",str(args.raw)))
            return raw_code_main(cmd)
        if args.command == "score-source-context":
            from .phase5m_source_context_candidate import main as source_pair_main
            if args.mode == "export":
                if args.questions_out is None or args.template_out is None:
                    parser.error("export needs --questions-out and --template-out")
                return source_pair_main([
                    "export", "--questions-out", str(args.questions_out),
                    "--template-out", str(args.template_out),
                ])
            if args.mode == "baseline":
                if args.strategy is None or args.out is None:
                    parser.error("baseline needs --strategy and --out")
                return source_pair_main([
                    "baseline", "--strategy", args.strategy, "--out", str(args.out),
                ])
            if args.predictions is None or args.out is None:
                parser.error("score needs --predictions and --out")
            return source_pair_main([
                "score", "--predictions", str(args.predictions), "--out", str(args.out),
            ])

        if args.command == "score-source-balanced":
            from .phase5k_source_blind_scorecard import main as balanced_main
            if args.mode == "audit":
                if args.out is None:
                    parser.error("audit needs --out")
                return balanced_main(["audit", "--out", str(args.out)])
            if args.mode == "export":
                if args.questions_out is None or args.template_out is None:
                    parser.error("export needs --questions-out and --template-out")
                return balanced_main([
                    "export", "--questions-out", str(args.questions_out),
                    "--template-out", str(args.template_out),
                ])
            if args.mode == "baseline":
                if args.strategy is None or args.out is None:
                    parser.error("baseline needs --strategy and --out")
                return balanced_main([
                    "baseline", "--strategy", args.strategy, "--out", str(args.out),
                ])
            if args.predictions is None or args.out is None:
                parser.error("score needs --predictions and --out")
            return balanced_main([
                "score", "--predictions", str(args.predictions), "--out", str(args.out),
            ])
        if args.command == "score-source-predictions":
            from .phase5f_evaluator_scorecard import main as scorecard_main
            if args.mode == "export":
                if args.challenge_out is None or args.template_out is None:
                    parser.error("export needs --challenge-out and --template-out")
                return scorecard_main([
                    "export", "--challenge-out", str(args.challenge_out),
                    "--template-out", str(args.template_out),
                ])
            if args.mode == "score":
                if args.predictions is None or args.out is None:
                    parser.error("score needs --predictions and --out")
                return scorecard_main([
                    "score", "--predictions", str(args.predictions), "--out", str(args.out),
                ])
            if args.strategy is None or args.out is None:
                parser.error("baseline needs --strategy and --out")
            return scorecard_main([
                "baseline", "--strategy", args.strategy, "--out", str(args.out),
            ])
        if args.command == "verify-source-review":
            params=[
                "--index",str(args.index),
                "--source-lock",str(args.source_lock),
                "--out",str(args.out),
            ]
            if args.requests is not None:
                params.extend(("--requests",str(args.requests)))
            if (args.flask_lock is None) != (args.flask_proof_b64 is None):
                parser.error("--flask-lock and --flask-proof-b64 must be provided together")
            if args.flask_lock is not None:
                from .phase5c_fifth_source_witness import main as verify_extended
                params.extend(("--flask-lock",str(args.flask_lock),
                               "--flask-proof-b64",str(args.flask_proof_b64)))
                return verify_extended(params)
            from .source_review_witness_gate import main as verify_main
            return verify_main(params)
        if args.command == "preflight":
            import json
            print(json.dumps(preflight_casebook(args.casebook, diagnostic_dir=args.diagnostic_dir), indent=2, sort_keys=True))
            return 0
        if args.command in ("check-scenarios", "export-scenarios", "audit-scenarios"):
            book = read_casebook(args.casebook)
            if args.command == "check-scenarios":
                import json
                print(json.dumps(readiness_report(book, base_dir=args.casebook.parent), indent=2, sort_keys=True))
                return 0
            if args.command == 'audit-scenarios':
                issues = verify_source_snapshots(book, args.casebook.parent)
                if issues:
                    raise ScenarioError('; '.join(issues))
                print('SOURCE AUDIT: pinned excerpts match checksums and local provenance; expert review still required')
                return 0
            output = export_reviewed(book, args.split, base_dir=args.casebook.parent)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(output, encoding="utf-8")
            print(f"EXPORTED: {output.count(chr(10))} reviewed scenario pairs")
            return 0
        if args.command == "fetch-osv":
            path = fetch_osv(args.advisory_id, args.directory)
            print(f"SNAPSHOT: {path}")
            return 0
        if args.command == "check-osv":
            record, metadata = verify_snapshot(args.snapshot, args.advisory)
            status = version_status(record, args.ecosystem, args.package, args.version)
            print(f"SOURCE-STATUS: {status}; sha256={metadata['sha256']}")
            if status == 'unknown' or (args.expect is not None and status != args.expect):
                return 2
            return 0
        ledger = load_ledger(args.ledger)
        if args.command == 'audit-snapshots':
            issues = audit_ledger_snapshots(ledger, args.directory, include_drafts=args.include_drafts)
            if issues:
                raise SourceError("\n".join(issues))
            print("SNAPSHOT AUDIT: verified source integrity and supported version labels (human review still required)")
            return 0
        if args.command == "validate":
            print(f"VALID: {len(ledger['evidence'])} evidence records; {len(ledger['pairs'])} pairs")
            return 0
        text = export_jsonl(ledger, args.split)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"EXPORTED: {text.count(chr(10))} reviewed {args.split} pairs to {args.out}")
        return 0
    except (LedgerError, ScenarioError, PreflightError, SourceError, OSError, ValueError) as exc:
        print(f"FALSUM ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
