"""Phase 3X: execute only the exact upstream Django intcomma function, safely.

The standalone function is extracted from two immutable original Git source
snapshots and their complete source Git blob SHA1s are checked. This is not
a full installed Django runtime, nor a live HTTP DoS or a throughput benchmark.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PARENT = "9cefdfc43f0bae696b56fa5a0bf22346f85affff"
FIXED = "55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9"
PARENT_BLOB = "23224779c5587f123a692a55370bffbd4dc8382f"
FIXED_BLOB = "2c26f8944a78da3cc378196d185a34cfd3e17d2c"
SRC_PATH = "django/contrib/humanize/templatetags/humanize.py"
MAX_INPUT_DIGITS = 3601


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def verify_file(path: Path, expected_git_blob: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Pinned Django source snapshot missing or symlinked")
    if git_blob_sha1(path.read_bytes()) != expected_git_blob:
        raise ValueError("Pinned Django source Git blob changed")


def source_function(path: Path):
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    matches = [node for node in tree.body
               if isinstance(node, ast.FunctionDef) and node.name == "intcomma"]
    if len(matches) != 1:
        raise ValueError("Expected exactly one real Django intcomma")
    fn = matches[0]
    # Decorators require Django's framework machinery. Strip *only* decorator
    # AST nodes and compile the original function itself without other module code.
    fn.decorator_list = []
    module = ast.Module(body=[fn], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {
        "re": re,
        "Decimal": __import__("decimal").Decimal,
        "number_format": lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("Localization must not run in this isolated experiment")
        ),
        "__builtins__": __builtins__,
    }
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["intcomma"]


def worker(path: Path, length: int):
    if not 1 <= length <= MAX_INPUT_DIGITS:
        raise ValueError("Input exceeds safe source test bound")
    function = source_function(path)
    # Match the standard Python default across runners. Not the OS resource limit.
    sys.setrecursionlimit(1000)
    # ASCII input. use_l10n=False reaches exactly the patched grouping logic
    # without importing or initializing the rest of the Django framework.
    value = "1" + "0" * (length - 1)
    try:
        output = function(value, use_l10n=False)
        if not isinstance(output, str):
            raise TypeError("Unexpected intcomma result")
        return {
            "outcome": "returned",
            "length": len(output),
            "sha256": hashlib.sha256(output.encode()).hexdigest(),
            "comma_count": output.count(","),
            "starts_with_comma": output.startswith(","),
        }
    except RecursionError:
        return {"outcome": "RecursionError", "length": None, "sha256": None,
                "comma_count": None, "starts_with_comma": None}


def child_run(path: Path, length: int, timeout: int = 12):
    cmd = [sys.executable, str(Path(__file__).resolve()),
           "--worker", str(path), str(length)]
    completed = subprocess.run(cmd, capture_output=True, text=True,
                               check=False, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError("Isolated source function subprocess failed: " +
                           completed.stderr[-900:])
    return json.loads(completed.stdout)


def expected_grouping(length: int) -> dict:
    value = "1" + "0" * (length - 1)
    grouped = ",".join(
        value[max(0, end - 3):end]
        for end in reversed(list(range(length, 0, -3)))
    )
    return {
        "outcome": "returned",
        "length": len(grouped),
        "sha256": hashlib.sha256(grouped.encode()).hexdigest(),
        "comma_count": grouped.count(","),
        "starts_with_comma": grouped.startswith(","),
    }


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--before", type=Path)
    p.add_argument("--after", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--worker", type=Path)
    p.add_argument("length", nargs="?", type=int)
    args = p.parse_args(argv)
    if args.worker is not None:
        if args.length is None:
            p.error("worker requires input length")
        print(json.dumps(worker(args.worker, args.length)))
        return 0
    if args.before is None or args.after is None or args.out is None:
        p.error("--before, --after and --out required")
    if args.out.exists() or args.out.is_symlink():
        p.error("Refusing to overwrite existing evidence")
    verify_file(args.before, PARENT_BLOB)
    verify_file(args.after, FIXED_BLOB)
    cases = []
    for length in (13, 12, MAX_INPUT_DIGITS):
        old_result = child_run(args.before, length)
        fixed_result = child_run(args.after, length)
        expected = expected_grouping(length)
        if length in (13, MAX_INPUT_DIGITS) and fixed_result != expected:
            raise AssertionError("Patched source must preserve oracle grouping in these two lengths")
        if length in (12, 13) and old_result != expected:
            raise AssertionError("Pre-fix short ordinary formatting must still work")
        if length == 12 and (fixed_result == expected or fixed_result["starts_with_comma"] is not True):
            raise AssertionError("Pinned patched source no longer reproduces observed leading-comma formatting discrepancy")
        if length == MAX_INPUT_DIGITS and old_result["outcome"] != "RecursionError":
            raise AssertionError("Long-input recursion did not reproduce with default Python recursion limit")
        cases.append({"digits":length, "before":old_result, "after":fixed_result,
                      "before_matches_grouping_oracle":old_result == expected,
                      "after_matches_grouping_oracle":fixed_result == expected})
    report = {
        "schema_version": 1,
        "status": "SOURCE_EXECUTED_DJANGO_INT_COMMA_SAFE_LONG_INPUT_COUNTERFACTUAL",
        "upstream": "django/django",
        "parent_commit": PARENT, "fixed_commit": FIXED,
        "primary_source_blobs_verified": True,
        "actual_pinned_function_extracted_and_executed": True,
        "full_installed_django_runtime": False,
        "http_server_or_production_dos_executed": False,
        "localization_disabled_for_isolation": True,
        "subprocess_timeout_seconds": 12,
        "python_runtime": sys.version.split()[0],
        "normalized_child_recursion_limit": 1000,
        "cases": cases,
        "patched_12_digit_localization_disabled_leading_comma_observed": True,
        "notice": "Long input is synthetic and bounded. A distinct 12-digit formatting mismatch is recorded rather than hidden. The test extracts the exact pinned function without loading Django; no real-world availability impact, release regression or traffic exposure is claimed."
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "short_pre_patch": cases[0]["before"]["outcome"],
        "fixed_12_digit_matches_oracle": cases[1]["after_matches_grouping_oracle"],
        "long_pre_patch": cases[2]["before"]["outcome"],
        "long_post_patch": cases[2]["after"]["outcome"],
        "full_django_installed": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
