"""Materialize only exact Git-blob-verified Axios URL helper revisions for Node behavior tests.

No HTTP requests are SENT by the test; it only calls the upstream URL builder.
This is a functional source comparison, not evidence of deployed SSRF.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Callable

from .real_fix_replay import fetch_raw, git_blob_sha, raw_url

PROJECT = "axios/axios"
PARENT = "8603e677c09fb81bd106999c194308dd230bc596"
FIX = "02c3c69ced0f8fd86407c23203835892313d7fde"
FILES = {
    "lib/core/buildFullPath.js": (
        "00b2b050a109be125f0837acf643f495981b0680",
        "553cffcb5e26bebe93577adae7c1f73f6cd0f293",
    ),
    "lib/helpers/isAbsoluteURL.js": (
        "43fea788a8291cb52a5c0f351837c4ddc8b8567f",
        "43fea788a8291cb52a5c0f351837c4ddc8b8567f",
    ),
    "lib/helpers/combineURLs.js": (
        "7c05d1ab0f7fb980c3df7d9c0052dfa34301c730",
        "7c05d1ab0f7fb980c3df7d9c0052dfa34301c730",
    ),
}


class AxiosEvidenceError(ValueError):
    """Refuse modified historical source or fabricated evidence."""


def materialize(destination: Path, reader: Callable[[str], bytes] = fetch_raw) -> dict:
    if destination.exists():
        raise AxiosEvidenceError("refusing to overwrite preexisting source evidence")
    sources = {}
    for name, ref in (("parent", PARENT), ("fixed", FIX)):
        sources[name] = []
        for path, ids in FILES.items():
            content = reader(raw_url(PROJECT, ref, path))
            expected = ids[0] if name == "parent" else ids[1]
            actual = git_blob_sha(content)
            if expected != actual:
                raise AxiosEvidenceError(f"{name}/{path}: actual git blob SHA mismatch")
            if len(content) > 25000 or not content.endswith(b"\n"):
                raise AxiosEvidenceError("unexpected upstream helper size or newline convention")
            sources[name].append((path,content,expected))
    for name, files in sources.items():
        for path,content,_ in files:
            dest=destination / name / path
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(content)
    manifest={
        "schema_version":1,"status":"PINNED_PUBLIC_AXIOS_SOURCE_FOR_LOCAL_BEHAVIOR_AUDIT",
        "upstream_repository":PROJECT,"parent_commit":PARENT,"fix_commit":FIX,
        "files":{key:[{"path":p,"git_blob_sha1":sha,"content_sha256":hashlib.sha256(body).hexdigest()}
                      for p,body,sha in records] for key,records in sources.items()},
        "no_network_http_requests_executed":True,
        "has_human_security_review":False,
        "proves_deployed_exploitability":False,
        "network_eligible":False,
    }
    (destination/"MANIFEST.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return manifest


def main(argv: list[str]|None=None) -> int:
    p=argparse.ArgumentParser(description="Fetch real pinned Axios 0.x baseURL helpers for non-network behavior regression")
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args(argv)
    try:
        result=materialize(args.out)
        print(json.dumps({"status":result["status"],"verified_files":sum(len(x) for x in result["files"].values()),
                          "network_eligible":False},indent=2))
        return 0
    except (AxiosEvidenceError,OSError,ValueError) as exc:
        p.exit(1,f"FALSUM AXIOS SOURCE ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
