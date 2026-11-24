"""Execute four original upstream Anchor Rust unit tests on pinned source.

No chain, wallet, deployment, or third-party service is used. The exact
fixed revision's test module is appended only to the affected source file.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "data/phase5av-solana-anchor-runtime-lock.json"
LOCK_BLOB = "dcc2b3f37e518a8d949f1d16627e40b6a60ad78a"
MARKER = b"#[cfg(test)]\nmod tests {\n"
PREFIX = "accounts::program::tests::"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def verified_checkout(folder, spec, source):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=folder, text=True).strip()
    require(head == spec["commit"], "checkout commit mismatch")
    clean = subprocess.check_output(["git", "status", "--porcelain"], cwd=folder, text=True)
    require(not clean, "checkout was modified before verification")
    for path, key in [(source, "source_blob"), ("Cargo.toml", "workspace_blob"),
                      ("lang/Cargo.toml", "lang_manifest_blob"), ("Cargo.lock", "cargo_lock_blob")]:
        require(git_blob((folder / path).read_bytes()) == spec[key],
                "unexpected upstream Git blob: " + path)


def main():
    require(len(sys.argv) == 4, "usage: script AFFECTED_DIR FIXED_DIR REPORT_DIR")
    affected, fixed, output = (Path(p).resolve() for p in sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    raw = LOCK.read_bytes()
    require(git_blob(raw) == LOCK_BLOB, "runtime protocol changed")
    lock = json.loads(raw)
    source = lock["source"]
    for name, folder in [("affected", affected), ("fixed", fixed)]:
        verified_checkout(folder, lock["revisions"][name], source)

    fixed_bytes = (fixed / source).read_bytes()
    require(fixed_bytes.count(MARKER) == 1, "ambiguous original test module")
    module = fixed_bytes[fixed_bytes.index(MARKER):]
    require(set(re.findall(rb"(?m)^    fn (program_\w+)\(", module)) ==
            {name.encode() for name in lock["expected"]["fixed"]},
            "original test names changed")
    original = (affected / source).read_bytes()
    require(MARKER not in original, "affected source already has the test module")
    (affected / source).write_bytes(original.rstrip(b"\n") + b"\n\n" + module)
    require((affected / source).read_bytes().endswith(module), "test overlay changed")
    print("Authenticated test module SHA256:", hashlib.sha256(module).hexdigest(), flush=True)

    report = {
        "scope": lock["scope"],
        "protocol_blob": LOCK_BLOB,
        "test_module_sha256": hashlib.sha256(module).hexdigest(),
        "revisions": lock["revisions"],
        "runs": {},
        "live_solana_integration": False,
        "independent_adoption": False,
        "network_ranking_improvement": False,
        "security_clearance": False,
    }
    report["rust_version"] = subprocess.check_output(
        ["rustup", "run", lock["rust"], "rustc", "--version"], text=True).strip()
    for name, folder in [("fixed", fixed), ("affected", affected)]:
        cmd = ["rustup", "run", lock["rust"], "cargo", "test", "--locked",
               "-p", "anchor-lang", "--lib", "accounts::program::tests",
               "--", "--test-threads=1"]
        env = dict(os.environ, CARGO_TERM_COLOR="never", RUST_BACKTRACE="0")
        # Use separate target directories; no stale test binaries across revisions.
        env["CARGO_TARGET_DIR"] = str(output / ("target-" + name))
        print("Executing", name, " ".join(cmd), flush=True)
        process = subprocess.run(cmd, cwd=folder, env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=1200)
        log = process.stdout
        (output / (name + ".log")).write_bytes(log)
        decoded = log.decode("utf-8", "replace")
        print(decoded[-16000:], flush=True)
        matches = re.findall(r"(?m)^test " + re.escape(PREFIX) +
                             r"(\w+) \.\.\. (ok|FAILED|ignored)$", decoded)
        observed = dict(matches)
        report["runs"][name] = {"exit_code": process.returncode, "observed": observed,
                                 "log_sha256": hashlib.sha256(log).hexdigest()}
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        require(len(matches) == len(observed) == 4 and observed == lock["expected"][name],
                "unexpected test outcomes; compilation errors are not regression evidence")
        if name == "fixed":
            require(process.returncode == 0, "fixed test command failed")
        else:
            require(process.returncode == 101 and "non-system key must be rejected" in decoded,
                    "affected revision did not fail at the exact original assertion")
        require(git_blob((folder / "Cargo.lock").read_bytes()) ==
                lock["revisions"][name]["cargo_lock_blob"], "Cargo lock mutated")
    report["verified_runtime_regression"] = True
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("VERIFIED: four fixed passes; exactly one expected affected assertion failure.")


if __name__ == "__main__":
    main()
