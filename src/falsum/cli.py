"""Command line entry point for evidence dataset quality checks and exports."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ledger import LedgerError, export_jsonl, load_ledger
from .scenarios import ScenarioError, read_casebook, readiness_report, export_reviewed
from .osv import SourceError, audit_ledger_snapshots, verify_snapshot, version_status
from .sources import fetch_osv


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
    casebook = commands.add_parser("check-scenarios", help="validate security-review draft scenarios")
    casebook.add_argument("casebook", type=Path)
    case_export = commands.add_parser("export-scenarios", help="export only fully reviewed scenario pairs")
    case_export.add_argument("casebook", type=Path)
    case_export.add_argument("--split", required=True, choices=("train", "validation", "holdout"))
    case_export.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command in ("check-scenarios", "export-scenarios"):
            book = read_casebook(args.casebook)
            if args.command == "check-scenarios":
                import json
                print(json.dumps(readiness_report(book), indent=2, sort_keys=True))
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
    except (LedgerError, ScenarioError, SourceError, OSError, ValueError) as exc:
        print(f"FALSUM ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
