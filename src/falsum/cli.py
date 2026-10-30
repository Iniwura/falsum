"""Command line entry point for evidence dataset quality checks and exports."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ledger import LedgerError, export_jsonl, load_ledger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="falsum")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="check ledger without publishing anything")
    validate.add_argument("ledger", type=Path)
    export = commands.add_parser("export", help="export reviewed pairs for a specified split")
    export.add_argument("ledger", type=Path)
    export.add_argument("--split", choices=("train", "validation", "holdout"), required=True)
    export.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        ledger = load_ledger(args.ledger)
        if args.command == "validate":
            print(f"VALID: {len(ledger['evidence'])} evidence records; {len(ledger['pairs'])} pairs")
            return 0
        text = export_jsonl(ledger, args.split)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"EXPORTED: {text.count(chr(10))} reviewed {args.split} pairs to {args.out}")
        return 0
    except (LedgerError, OSError, ValueError) as exc:
        print(f"FALSUM ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
